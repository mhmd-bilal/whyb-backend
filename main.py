from fastapi import FastAPI, HTTPException, Depends, Query, Request
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
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from bs4 import BeautifulSoup
import time
import requests
from pydantic import BaseModel
from typing import Optional
import base64
import os
from dotenv import load_dotenv, dotenv_values
from colorthief import ColorThief  # type: ignore
from io import BytesIO
import spotipy  # type: ignore
from spotipy.oauth2 import SpotifyClientCredentials  # type: ignore
from fastapi.responses import JSONResponse

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def rgb_to_hex(rgb):
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def get_brightness(rgb):
    r, g, b = rgb
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def get_high_contrast_color(image_url):
    response = requests.get(image_url)
    img = BytesIO(response.content)

    color_thief = ColorThief(img)
    dominant_color = color_thief.get_color(quality=1)

    brightness = get_brightness(dominant_color)

    if brightness < 128:
        context_color = rgb_to_hex((255, 255, 255))
    else:
        context_color = rgb_to_hex((0, 0, 0))

    return context_color


class Post(BaseModel):
    song_url: str
    caption: str


class User(BaseModel):
    name: str
    username: str
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
client = motor.motor_asyncio.AsyncIOMotorClient(os.getenv("MONGO_URL"))
db = client["whyb_data"]

bearer_scheme = HTTPBearer()


def get_spotify_details(link):
    client_id = os.getenv("SPOTIFY_CLIENT_ID")
    client_secret = os.getenv("SPOTIFY_CLIENT_SECRET")

    auth_manager = SpotifyClientCredentials(
        client_id=client_id, client_secret=client_secret
    )
    sp = spotipy.Spotify(auth_manager=auth_manager)

    track_id = link.split("/")[-1].split("?")[0]

    track = sp.track(track_id)

    return {
        "song_name": track["name"],
        "album": track["album"]["name"],
        "song_image": track["album"]["images"][0]["url"],
        "song_url": link,
        "song_provider": "Spotify",
        "song_duration": track["duration_ms"] / 1000,  # Convert duration to seconds
        "artist": track["artists"][0]["name"],
    }


def get_youtube_details(link):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }
    response = requests.get(link, headers=headers)

    if response.status_code != 200:
        return {"error": "Failed to fetch YouTube page"}

    soup = BeautifulSoup(response.text, "html.parser")

    title = soup.find("meta", property="og:title")
    description = soup.find("meta", property="og:description")
    image = soup.find("meta", property="og:image")

    return {
        "song_name": title["content"] if title else "Title not found",
        "album": description["content"] if description else "Description not found",
        "song_image": image["content"] if image else "Image not found",
        "song_url": link,
        "song_provider": "YouTube",
        "song_duration": "N/A",
        "artist": "Unknown Artist",
    }


def get_song_details(link):
    if "spotify.com" in link:
        return get_spotify_details(link)
    elif "youtube.com" in link or "youtu.be" in link:
        return get_youtube_details(link)
    else:
        return {"error": "Unsupported link. Please provide a Spotify or YouTube link."}


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def create_access_token(
    data: dict,
    # expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
):
    to_encode = data.copy()
    # expire = datetime.utcnow() + expires_delta
    # to_encode.update({"exp": expire})
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
        return JSONResponse(status_code=400, content=ErrorResponse(message="Email already registered").dict())

    hashed_password = hash_password(user.password)

    user_data = user.dict()
    user_data["password"] = hashed_password

    result = await db["users"].insert_one(user_data)
    return {"id": str(result.inserted_id), "message": "User created successfully"}


@app.post("/signin/")
async def signin(form_data: UserLogin):
    user = await db["users"].find_one({"email": form_data.email})
    if not user:
        return JSONResponse(status_code=401, content=ErrorResponse(message="Invalid credentials").dict())

    hashed_password = hash_password(form_data.password)
    if hashed_password != user["password"]:
        return JSONResponse(status_code=401, content=ErrorResponse(message="Invalid credentials").dict())

    # Create access token
    access_token = create_access_token(data={"sub": user["email"]})
    return {
        "user_id": str(user["_id"]),
        "access_token": access_token,
        "token_type": "Bearer",
        "message": "You are logged in.",
    }


@app.get("/protected/")
async def protected_route(current_user: str = Depends(get_current_user)):
    return {"message": f"Welcome {current_user}, you are signed in!"}


from bson import ObjectId


@app.get("/user/{user_id}/")
async def get_user(user_id: str, current_user: str = Depends(get_current_user)):
    try:
        user_object_id = ObjectId(user_id)
    except Exception:
        return JSONResponse(status_code=400, content=ErrorResponse(message="Invalid user ID format. Please provide a valid ID.").dict())

    user = await db["users"].find_one({"_id": user_object_id})
    if not user:
        return JSONResponse(status_code=404, content=ErrorResponse(message="User not found. Please check the ID and try again.").dict())

    user["_id"] = str(user["_id"])

    posts_count = await db["posts"].count_documents({"user_id": user_object_id})
    comments_count = await db["comments"].count_documents({"user_id": user_object_id})
    likes_count = await db["likes"].count_documents({"user_id": user_object_id})
    followers_count = await db["follows"].count_documents(
        {"followee_id": user_object_id}
    )
    following_count = await db["follows"].count_documents(
        {"follower_id": user_object_id}
    )

    posts = await db["posts"].find({"user_id": user_object_id}).to_list(length=100)
    total_likes_count = 0

    for post in posts:
        post["_id"] = str(post["_id"])
        post["user_id"] = str(post["user_id"])

        post_likes_count = await db["likes"].count_documents(
            {"post_id": ObjectId(post["_id"])}
        )
        post["likes_count"] = post_likes_count
        total_likes_count += post_likes_count

        post_user = await db["users"].find_one({"_id": ObjectId(post["user_id"])})
        post["username"] = post_user["username"] if post_user else "Unknown"

    comments = (
        await db["comments"].find({"user_id": user_object_id}).to_list(length=100)
    )
    for comment in comments:
        comment["_id"] = str(comment["_id"])
        comment["user_id"] = str(comment["user_id"])
        comment["post_id"] = str(comment["post_id"])
        comment["date"] = str(comment["date"])


        post = await db["posts"].find_one({"_id": ObjectId(comment["post_id"])})
        comment["song_image"] = post.get("song_image", None) if post else None

    return {
        "user": user,
        "posts": posts,
        "comments": comments,
        "stats": {
            "posts_count": posts_count,
            "comments_count": comments_count,
            "likes_count": total_likes_count,
            "followers_count": followers_count,
            "following_count": following_count,
        },
    }


class PostDetail(BaseModel):
    song_url: str
    song_name: str
    song_image: str
    song_duration: str
    song_provider: str
    album: str
    artist: str
    caption: str


@app.get("/posts/")
async def get_posts(
    current_user: str = Depends(get_current_user), search: Optional[str] = Query(None)
):
    if not search:
        posts = await db["posts"].find({}).to_list(length=100)
    else:
        posts_pipeline = [
            {
                "$match": {
                    "$or": [
                        {"song_name": {"$regex": search, "$options": "i"}},
                        {"artist": {"$regex": search, "$options": "i"}},
                        {"album": {"$regex": search, "$options": "i"}},
                        {"caption": {"$regex": search, "$options": "i"}},
                    ]
                }
            }
        ]
        posts = await db["posts"].aggregate(posts_pipeline).to_list(length=100)

        users_pipeline = [
            {
                "$match": {
                    "$or": [
                        {"name": {"$regex": search, "$options": "i"}},
                        {"username": {"$regex": search, "$options": "i"}},
                    ]
                }
            },
            {
                "$lookup": {
                    "from": "posts",
                    "localField": "_id",
                    "foreignField": "user_id",
                    "as": "user_posts",
                }
            },
            {"$unwind": "$user_posts"},
            {
                "$project": {
                    "_id": "$user_posts._id",
                    "song_url": "$user_posts.song_url",
                    "song_name": "$user_posts.song_name",
                    "song_image": "$user_posts.song_image",
                    "song_duration": "$user_posts.song_duration",
                    "song_provider": "$user_posts.song_provider",
                    "album": "$user_posts.album",
                    "artist": "$user_posts.artist",
                    "caption": "$user_posts.caption",
                    "user_id": "$user_posts.user_id",
                    "date": "$user_posts.date",
                    "context_color": "$user_posts.context_color",
                }
            },
        ]
        user_posts = await db["users"].aggregate(users_pipeline).to_list(length=100)

        posts = {str(post["_id"]): post for post in posts + user_posts}.values()
        posts = list(posts)

    for post in posts:
        post["_id"] = str(post["_id"])
        post["user_id"] = str(post["user_id"])

        user_id = ObjectId(post["user_id"])
        user = await db["users"].find_one({"_id": user_id})
        if user:
            post["name"] = user.get("name", "Unknown")
            post["username"] = user.get("username", "Unknown")

        post["likes_count"] = await db["likes"].count_documents(
            {"post_id": ObjectId(post["_id"])}
        )

    return {"posts": posts}


@app.post("/post/")
async def create_post(post: Post, current_user: str = Depends(get_current_user)):
    user = await db["users"].find_one({"email": current_user})
    if not user:
        return JSONResponse(status_code=404, content=ErrorResponse(message="User not found").dict())

    song_data = get_song_details(post.song_url)

    if "error" in song_data:
        return JSONResponse(status_code=400, content=ErrorResponse(message=song_data["error"]).dict())

    image_url = song_data["song_image"]
    response = requests.get(image_url)
    img = BytesIO(response.content)

    color_thief = ColorThief(img)
    dominant_color = color_thief.get_color(quality=1)
    rgb_color = dominant_color
    context_color = rgb_to_hex(rgb_color)

    post_data = {
        "song_url": song_data["song_url"],
        "song_name": song_data["song_name"],
        "song_image": song_data["song_image"],
        "song_duration": song_data["song_duration"],
        "song_provider": song_data["song_provider"],
        "album": song_data["album"],
        "artist": song_data["artist"],
        "caption": post.caption,
        "user_id": user["_id"],
        "date": datetime.utcnow(),
        "context_color": context_color,
    }

    result = await db["posts"].insert_one(post_data)
    return {"message": "Post created successfully", "post_id": str(result.inserted_id)}


@app.get("/posts/{post_id}/")
async def get_post(post_id: str, current_user: str = Depends(get_current_user)):
    try:
        post_object_id = ObjectId(post_id)
    except Exception:
        return JSONResponse(status_code=400, content=ErrorResponse(message="Invalid post ID format. Please provide a valid ID.").dict())

    post = await db["posts"].find_one({"_id": post_object_id})
    if not post:
        return JSONResponse(status_code=404, content=ErrorResponse(message="Post not found. Please check the ID and try again.").dict())

    comments = (
        await db["comments"].find({"post_id": post_object_id}).to_list(length=100)
    )
    for comment in comments:
        comment["_id"] = str(comment["_id"])
        comment["user_id"] = str(comment["user_id"])
        comment["post_id"] = str(comment["post_id"])
        comment_user = await db["users"].find_one({"_id": ObjectId(comment["user_id"])})
        if comment_user:
            comment["name"] = comment_user.get("name")
            comment["username"] = comment_user.get("username")

    likes_count = await db["likes"].count_documents({"post_id": post_object_id})

    # Check if the current user has liked the post
    user = await db["users"].find_one({"email": current_user})
    liked = False
    if user:
        liked = (
            await db["likes"].find_one(
                {"user_id": user["_id"], "post_id": post_object_id}
            )
            is not None
        )

    # Convert ObjectId to string for JSON serialization
    post["_id"] = str(post["_id"])
    post["user_id"] = str(post["user_id"])

    # Get post author info
    post_user = await db["users"].find_one({"_id": ObjectId(post["user_id"])})
    if post_user:
        post["name"] = post_user.get("name")
        post["username"] = post_user.get("username")

    return {
        "post": post,
        "comments": comments,
        "likes_count": likes_count,
        "liked": liked,  # Return whether the current user has liked the post
    }


class Comment(BaseModel):
    comment: str


@app.post("/posts/{post_id}/comment/")
async def add_comment(
    post_id: str, comment: Comment, current_user: str = Depends(get_current_user)
):
    try:
        post_object_id = ObjectId(post_id)
    except Exception:
        return JSONResponse(status_code=400, content=ErrorResponse(message="Invalid post ID format. Please provide a valid ID.").dict())

    user = await db["users"].find_one({"email": current_user})
    if not user:
        return JSONResponse(status_code=404, content=ErrorResponse(message="User not found. Please log in and try again.").dict())

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
        return JSONResponse(status_code=400, content=ErrorResponse(message="Invalid post ID format. Please provide a valid ID.").dict())

    user = await db["users"].find_one({"email": current_user})
    if not user:
        return JSONResponse(status_code=404, content=ErrorResponse(message="User not found. Please log in and try again.").dict())

    existing_like = await db["likes"].find_one({"user_id": user["_id"], "post_id": post_object_id})
    if existing_like:
        await db["likes"].delete_one({"_id": existing_like["_id"]})
        return {"message": "Like removed successfully."}
    else:
        like_data = {
            "user_id": user["_id"],
            "post_id": post_object_id,
            "date": datetime.utcnow(),
        }
        await db["likes"].insert_one(like_data)
        return {"message": "Post liked successfully."}


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

    # Fetch comments by user_id
    comments = (
        await db["comments"].find({"user_id": user_object_id}).to_list(length=100)
    )

    # Initialize a list to store enriched comments
    enriched_comments = []

    for comment in comments:
        comment["_id"] = str(comment["_id"])
        comment["user_id"] = str(comment["user_id"])
        comment["post_id"] = str(comment["post_id"])

        post = await db["posts"].find_one({"_id": ObjectId(comment["post_id"])})
        if post:
            comment["song_image"] = post.get("song_image", None)
        else:
            comment["song_image"] = None

        enriched_comments.append(comment)

    return {"comments": enriched_comments}


class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    bio: Optional[str] = None


@app.put("/user/{user_id}/")
async def update_user(
    user_id: str, user_data: UserUpdate, current_user: str = Depends(get_current_user)
):
    try:
        user_object_id = ObjectId(user_id)
    except Exception:
        return JSONResponse(status_code=400, content=ErrorResponse(message="Invalid user ID format. Please provide a valid ID.").dict())

    user = await db["users"].find_one({"email": current_user})
    if not user or str(user["_id"]) != user_id:
        return JSONResponse(status_code=403, content=ErrorResponse(message="Not authorized to update this user.").dict())

    update_data = {
        k: v for k, v in user_data.dict(exclude_unset=True).items() if v is not None
    }

    if not update_data:
        return JSONResponse(status_code=400, content=ErrorResponse(message="No valid update data provided.").dict())

    if "email" in update_data:
        existing_user = await db["users"].find_one(
            {"email": update_data["email"], "_id": {"$ne": user_object_id}}
        )
        if existing_user:
            return JSONResponse(status_code=400, content=ErrorResponse(message="Email already in use.").dict())

    result = await db["users"].update_one(
        {"_id": user_object_id}, {"$set": update_data}
    )

    if result.modified_count == 0:
        return JSONResponse(status_code=404, content=ErrorResponse(message="User not found.").dict())

    updated_user = await db["users"].find_one({"_id": user_object_id})
    updated_user["_id"] = str(updated_user["_id"])

    return {
        "message": "User updated successfully",
        "user": {
            "name": updated_user["name"],
            "email": updated_user["email"],
            "bio": updated_user.get("bio", ""),
        },
    }


# Define a custom error response model
class ErrorResponse(BaseModel):
    message: str
