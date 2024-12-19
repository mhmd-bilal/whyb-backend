from fastapi import FastAPI, HTTPException, Depends, status, Header
from pydantic import BaseModel
from typing import Optional
from fastapi.security import (
    OAuth2PasswordRequestForm,
    HTTPBearer,
    HTTPAuthorizationCredentials,
)
import motor.motor_asyncio
import hashlib
import jwt
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware

import os
from dotenv import load_dotenv, dotenv_values

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM =  os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 30 


# Pydantic models
class User(BaseModel):
    name: str
    email: str
    password: str
    bio: Optional[str] = None


class UserLogin(BaseModel):
    email: str
    password: str


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or specify domains like ["http://localhost:3000"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
client = motor.motor_asyncio.AsyncIOMotorClient( os.getenv("MONGO_URL"))
db = client["whyb_data"]

# Security settings for OAuth2 password flow
bearer_scheme = HTTPBearer()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def create_access_token(
    data: dict,
    expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    token = credentials.credentials
    payload = verify_token(token)
    email: str = payload.get("sub")
    if email is None:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    return email


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.post("/signup/")
async def signup(user: User):
    existing_user = await db["users"].find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = hash_password(user.password)

    user_data = user.dict()
    user_data["password"] = hashed_password

    result = await db["users"].insert_one(user_data)
    return {"id": str(result.inserted_id), "message": "User created successfully"}


@app.post("/signin/")
async def signin(form_data: UserLogin):
    user = await db["users"].find_one({"email": form_data.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    hashed_password = hash_password(form_data.password)
    if hashed_password != user["password"]:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Create access token
    access_token = create_access_token(data={"sub": user["email"]})
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "message": "You are logged in.",
    }


# Protected endpoint (Example)
@app.get("/protected/")
async def protected_route(current_user: str = Depends(get_current_user)):
    return {"message": f"Welcome {current_user}, you are signed in!"}


from bson import ObjectId


@app.get("/user/{user_id}/")
async def get_user(user_id: str, current_user: str = Depends(get_current_user)):
    try:
        # Convert the string user_id to ObjectId
        user_object_id = ObjectId(user_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid user ID format")

    user = await db["users"].find_one({"_id": user_object_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Convert the ObjectId to a string for JSON serialization
    user["_id"] = str(user["_id"])

    return {"user": user}


class Post(BaseModel):
    song_url: str
    song_name: str
    song_image: str
    song_duration: str
    song_provider: str
    album: str
    artist: str
    caption: str


@app.get("/posts/")
async def get_posts(current_user: str = Depends(get_current_user)):
    posts = await db["posts"].find().to_list(length=100)
    for post in posts:
        post["_id"] = str(post["_id"])
        post["user_id"] = str(post["user_id"])
    return {"posts": posts}


@app.post("/post/")
async def create_post(post: Post, current_user: str = Depends(get_current_user)):
    user = await db["users"].find_one({"email": current_user})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    post_data = post.dict()
    post_data["user_id"] = user["_id"]
    post_data["date"] = datetime.utcnow()

    result = await db["posts"].insert_one(post_data)
    return {"message": "Post created successfully", "post_id": str(result.inserted_id)}


@app.get("/posts/{post_id}/")
async def get_post(post_id: str, current_user: str = Depends(get_current_user)):
    try:
        post_object_id = ObjectId(post_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid post ID format")

    post = await db["posts"].find_one({"_id": post_object_id})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    post["_id"] = str(post["_id"])
    post["user_id"] = str(post["user_id"])
    return {"post": post}


class Comment(BaseModel):
    comment: str


@app.post("/posts/{post_id}/comment/")
async def add_comment(
    post_id: str, comment: Comment, current_user: str = Depends(get_current_user)
):
    try:
        post_object_id = ObjectId(post_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid post ID format")

    user = await db["users"].find_one({"email": current_user})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    comment_data = comment.dict()
    comment_data["user_id"] = user["_id"]
    comment_data["post_id"] = post_object_id
    comment_data["date"] = datetime.utcnow()

    result = await db["comments"].insert_one(comment_data)
    return {
        "message": "Comment added successfully",
        "comment_id": str(result.inserted_id),
    }


@app.post("/posts/{post_id}/like/")
async def add_like(post_id: str, current_user: str = Depends(get_current_user)):
    try:
        post_object_id = ObjectId(post_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid post ID format")

    user = await db["users"].find_one({"email": current_user})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    existing_like = await db["likes"].find_one(
        {"user_id": user["_id"], "post_id": post_object_id}
    )
    if existing_like:
        raise HTTPException(status_code=400, detail="Post already liked")

    like_data = {
        "user_id": user["_id"],
        "post_id": post_object_id,
        "date": datetime.utcnow(),
    }

    result = await db["likes"].insert_one(like_data)
    return {"message": "Post liked successfully"}


@app.post("/users/{user_id}/follow/")
async def follow_user(user_id: str, current_user: str = Depends(get_current_user)):
    try:
        followee_object_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID format")

    user = await db["users"].find_one({"email": current_user})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    existing_follow = await db["follows"].find_one(
        {"follower_id": user["_id"], "followee_id": followee_object_id}
    )
    if existing_follow:
        raise HTTPException(status_code=400, detail="Already following this user")

    follow_data = {
        "follower_id": user["_id"],
        "followee_id": followee_object_id,
        "date": datetime.utcnow(),
    }

    result = await db["follows"].insert_one(follow_data)
    return {"message": "User followed successfully"}


@app.get("/user/{user_id}/posts/")
async def get_user_posts(user_id: str, current_user: str = Depends(get_current_user)):
    try:
        user_object_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID format")

    posts = await db["posts"].find({"user_id": user_object_id}).to_list(length=100)
    for post in posts:
        post["_id"] = str(post["_id"])
        post["user_id"] = str(post["user_id"])
    return {"posts": posts}


@app.get("/user/{user_id}/comments/")
async def get_user_comments(
    user_id: str, current_user: str = Depends(get_current_user)
):
    try:
        user_object_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID format")

    comments = (
        await db["comments"].find({"user_id": user_object_id}).to_list(length=100)
    )
    for comment in comments:
        comment["_id"] = str(comment["_id"])
        comment["user_id"] = str(comment["user_id"])
        comment["post_id"] = str(comment["post_id"])
    return {"comments": comments}
