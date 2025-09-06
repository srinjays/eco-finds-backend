# main.py
# Single-file FastAPI backend for Eco Finds (basic, hackathon-ready)

import os
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import List, Optional
from PIL import Image
import shutil
import uuid

# ---------------- CONFIG ----------------
JWT_SECRET = os.environ.get("JWT_SECRET", "supersecret_eco_finds_change_me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10  # as requested

BASE_DIR = os.path.dirname(__file__)
MEDIA_DIR = os.path.join(BASE_DIR, "media")
THUMB_DIR = os.path.join(MEDIA_DIR, "thumbs")
os.makedirs(MEDIA_DIR, exist_ok=True)
os.makedirs(THUMB_DIR, exist_ok=True)

DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'eco_finds.db')}")

# ---------------- DATABASE ----------------
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ---------------- MODELS ----------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, unique=True, index=True)
    phone = Column(String, unique=True, index=True)
    password = Column(String)
    avatar = Column(String, nullable=True)
    is_admin = Column(Boolean, default=False)
    verified = Column(Boolean, default=False)

    listings = relationship("Listing", back_populates="owner")
    reviews_given = relationship("Review", back_populates="author")

class Listing(Base):
    __tablename__ = "listings"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(Text)
    price = Column(Float)
    negotiable = Column(Boolean, default=True)
    category = Column(String, index=True)
    condition = Column(String)
    location = Column(String, index=True)
    brand = Column(String, nullable=True)
    status = Column(String, default="draft")  # draft, published, reserved, sold
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="listings")
    images = relationship("Image", back_populates="listing")

class Image(Base):
    __tablename__ = "images"
    id = Column(Integer, primary_key=True, index=True)
    filepath = Column(String)
    thumbpath = Column(String)
    listing_id = Column(Integer, ForeignKey("listings.id"))
    listing = relationship("Listing", back_populates="images")

class Offer(Base):
    __tablename__ = "offers"
    id = Column(Integer, primary_key=True, index=True)
    listing_id = Column(Integer, ForeignKey("listings.id"))
    buyer_id = Column(Integer, ForeignKey("users.id"))
    amount = Column(Float)
    status = Column(String, default="pending")  # pending, accepted, rejected, expired, counter
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    counter_of = Column(Integer, nullable=True)  # offer id if this is a counter

class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True, index=True)
    listing_id = Column(Integer, ForeignKey("listings.id"))
    buyer_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String, default="created")  # created -> paid -> picked -> completed -> cancelled
    created_at = Column(DateTime, default=datetime.utcnow)

class Chat(Base):
    __tablename__ = "chats"
    id = Column(Integer, primary_key=True, index=True)
    listing_id = Column(Integer, ForeignKey("listings.id"))
    user1 = Column(Integer, ForeignKey("users.id"))
    user2 = Column(Integer, ForeignKey("users.id"))

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    chat_id = Column(Integer, ForeignKey("chats.id"))
    sender_id = Column(Integer, ForeignKey("users.id"))
    text = Column(Text)
    image = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Review(Base):
    __tablename__ = "reviews"
    id = Column(Integer, primary_key=True, index=True)
    listing_id = Column(Integer, ForeignKey("listings.id"))
    author_id = Column(Integer, ForeignKey("users.id"))
    rating = Column(Integer)
    comment = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    author = relationship("User", back_populates="reviews_given")

Base.metadata.create_all(bind=engine)

# ---------------- SECURITY ----------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str):
    return pwd_context.verify(plain, hashed)

def create_token(data: dict, expires_minutes:int = ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.email==email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ---------------- FASTAPI APP ----------------
app = FastAPI(title="Eco Finds Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change to your domain later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- HELPERS ----------------
def save_upload(file: UploadFile, folder=MEDIA_DIR):
    ext = os.path.splitext(file.filename)[1]
    fname = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(folder, fname)
    with open(path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    # create thumbnail
    try:
        img = Image.open(path)
        img.thumbnail((400,400))
        thumb_name = f"thumb_{fname}"
        thumb_path = os.path.join(THUMB_DIR, thumb_name)
        img.save(thumb_path)
    except Exception:
        thumb_path = ""
    return path, thumb_path

# ---------------- Pydantic Schemas ----------------
class SignupSchema(BaseModel):
    name: str
    email: str
    phone: str
    password: str

class ListingCreateSchema(BaseModel):
    title: str
    description: str
    price: float
    negotiable: Optional[bool] = True
    category: Optional[str] = None
    condition: Optional[str] = None
    location: Optional[str] = None
    brand: Optional[str] = None
    status: Optional[str] = "draft"

# ---------------- AUTH ROUTES ----------------
@app.post("/auth/signup")
def signup(data: SignupSchema, db: SessionLocal = Depends(get_db)):
    if db.query(User).filter((User.email==data.email) | (User.phone==data.phone)).first():
        raise HTTPException(status_code=400, detail="Email or phone already registered")
    u = User(name=data.name, email=data.email, phone=data.phone, password=hash_password(data.password))
    db.add(u); db.commit(); db.refresh(u)
    return {"message":"signup success"}

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: SessionLocal = Depends(get_db)):
    # OAuth2PasswordRequestForm uses 'username' field → we'll put email there
    user = db.query(User).filter(User.email==form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token({"sub": user.email})
    return {"access_token": token, "token_type":"bearer", "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES*60}

# endpoint to upload avatar
@app.post("/auth/avatar")
def upload_avatar(file: UploadFile = File(...), current: User = Depends(get_current_user), db: SessionLocal = Depends(get_db)):
    path, thumb = save_upload(file)
    current.avatar = path
    db.add(current); db.commit()
    return {"avatar": path}

# ---------------- LISTINGS ----------------
@app.post("/listings")
def create_listing(payload: ListingCreateSchema, db: SessionLocal = Depends(get_db), current: User = Depends(get_current_user)):
    l = Listing(title=payload.title, description=payload.description, price=payload.price,
                negotiable=payload.negotiable, category=payload.category, condition=payload.condition,
                location=payload.location, brand=payload.brand, status=payload.status, owner_id=current.id)
    db.add(l); db.commit(); db.refresh(l)
    return {"message":"listing created", "id": l.id}

@app.post("/listings/{listing_id}/images")
def upload_listing_images(listing_id: int, files: List[UploadFile] = File(...), db: SessionLocal = Depends(get_db), current: User = Depends(get_current_user)):
    listing = db.query(Listing).filter(Listing.id==listing_id).first()
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found")
    if listing.owner_id != current.id:
        raise HTTPException(status_code=403, detail="Not owner")
    saved = []
    for f in files:
        p, t = save_upload(f)
        img = Image(filepath=p, thumbpath=t, listing_id=listing.id)
        db.add(img); db.commit(); db.refresh(img)
        saved.append({"id": img.id, "path": p, "thumb": t})
    return {"uploaded": saved}

@app.get("/listings")
def get_listings(q: Optional[str]=None, category: Optional[str]=None, min_price: Optional[float]=None,
                 max_price: Optional[float]=None, location: Optional[str]=None, sort: Optional[str]=None,
                 db: SessionLocal = Depends(get_db), page: int = 1, per_page: int = 20):
    query = db.query(Listing).filter(Listing.status=="published")
    if q:
        query = query.filter(Listing.title.contains(q) | Listing.description.contains(q))
    if category:
        query = query.filter(Listing.category==category)
    if min_price is not None:
        query = query.filter(Listing.price >= min_price)
    if max_price is not None:
        query = query.filter(Listing.price <= max_price)
    if location:
        query = query.filter(Listing.location==location)
    if sort == "price_asc":
        query = query.order_by(Listing.price.asc())
    elif sort == "price_desc":
        query = query.order_by(Listing.price.desc())
    else:
        query = query.order_by(Listing.id.desc())
    total = query.count()
    results = query.offset((page-1)*per_page).limit(per_page).all()
    out = []
    for l in results:
        out.append({
            "id": l.id, "title": l.title, "price": l.price, "description": l.description,
            "category": l.category, "condition": l.condition, "location": l.location,
            "brand": l.brand, "status": l.status, "owner_id": l.owner_id,
            "images": [{"id":img.id, "path": img.filepath, "thumb": img.thumbpath} for img in l.images]
        })
    return {"total": total, "page": page, "per_page": per_page, "results": out}

@app.get("/listings/{listing_id}")
def get_listing(listing_id:int, db: SessionLocal = Depends(get_db)):
    l = db.query(Listing).filter(Listing.id==listing_id).first()
    if not l: raise HTTPException(status_code=404, detail="Not found")
    return {
        "id": l.id, "title": l.title, "price": l.price, "description": l.description,
        "category": l.category, "condition": l.condition, "location": l.location,
        "brand": l.brand, "status": l.status, "owner_id": l.owner_id,
        "images": [{"id":img.id, "path": img.filepath, "thumb": img.thumbpath} for img in l.images]
    }

@app.post("/listings/{listing_id}/publish")
def publish_listing(listing_id:int, db: SessionLocal = Depends(get_db), current:User = Depends(get_current_user)):
    l = db.query(Listing).filter(Listing.id==listing_id).first()
    if not l: raise HTTPException(status_code=404, detail="not found")
    if l.owner_id != current.id: raise HTTPException(status_code=403, detail="not owner")
    l.status = "published"
    db.add(l); db.commit()
    return {"message":"published"}

# ---------------- OFFERS (BARGAIN) ----------------
@app.post("/offers")
def make_offer(listing_id: int = Form(...), amount: float = Form(...), db: SessionLocal = Depends(get_db), current: User = Depends(get_current_user)):
    listing = db.query(Listing).filter(Listing.id==listing_id).first()
    if not listing: raise HTTPException(status_code=404, detail="Listing not found")
    # simple rule checks (min 3% of price)
    min_allowed = listing.price * 0.03
    if amount < min_allowed:
        raise HTTPException(status_code=400, detail="Offer too low")
    expires = datetime.utcnow() + timedelta(hours=24)
    offer = Offer(listing_id=listing.id, buyer_id=current.id, amount=amount, status="pending", created_at=datetime.utcnow(), expires_at=expires)
    db.add(offer); db.commit(); db.refresh(offer)
    return {"message":"offer created", "offer_id": offer.id}

@app.post("/offers/{offer_id}/counter")
def counter_offer(offer_id:int, amount: float = Form(...), db: SessionLocal = Depends(get_db), current: User = Depends(get_current_user)):
    base = db.query(Offer).filter(Offer.id==offer_id).first()
    if not base: raise HTTPException(status_code=404, detail="Offer not found")
    # allow counter (max counters not tracked here for simplicity)
    expires = datetime.utcnow() + timedelta(hours=24)
    counter = Offer(listing_id=base.listing_id, buyer_id=current.id, amount=amount, status="counter", created_at=datetime.utcnow(), expires_at=expires, counter_of=offer_id)
    db.add(counter); db.commit(); db.refresh(counter)
    return {"message":"counter created", "counter_id": counter.id}

@app.post("/offers/{offer_id}/accept")
def accept_offer(offer_id:int, db: SessionLocal = Depends(get_db), current: User = Depends(get_current_user)):
    offer = db.query(Offer).filter(Offer.id==offer_id).first()
    if not offer: raise HTTPException(status_code=404, detail="Offer not found")
    listing = db.query(Listing).filter(Listing.id==offer.listing_id).first()
    if listing.owner_id != current.id:
        raise HTTPException(status_code=403, detail="Only owner can accept")
    offer.status = "accepted"
    listing.status = "reserved"  # lock listing
    db.add(offer); db.add(listing); db.commit()
    return {"message":"offer accepted"}

@app.get("/offers/{listing_id}")
def list_offers(listing_id:int, db: SessionLocal = Depends(get_db), current: User = Depends(get_current_user)):
    # only buyer or seller can view offers for privacy
    listing = db.query(Listing).filter(Listing.id==listing_id).first()
    if not listing: raise HTTPException(status_code=404, detail="Listing not found")
    if current.id != listing.owner_id:
        # show only offers by this user if not owner
        offers = db.query(Offer).filter(Offer.listing_id==listing_id, Offer.buyer_id==current.id).all()
    else:
        offers = db.query(Offer).filter(Offer.listing_id==listing_id).all()
    out = [{"id":o.id, "amount": o.amount, "status": o.status, "buyer_id": o.buyer_id, "expires_at": o.expires_at} for o in offers]
    return out

# ---------------- ORDERS ----------------
@app.post("/orders")
def create_order(listing_id: int = Form(...), offer_id: Optional[int] = Form(None), db: SessionLocal = Depends(get_db), current: User = Depends(get_current_user)):
    listing = db.query(Listing).filter(Listing.id==listing_id).first()
    if not listing: raise HTTPException(status_code=404, detail="Listing not found")
    # simple create order
    o = Order(listing_id=listing.id, buyer_id=current.id, status="created", created_at=datetime.utcnow())
    db.add(o); db.commit(); db.refresh(o)
    return {"message":"order created", "order_id": o.id}

@app.post("/orders/{order_id}/complete")
def complete_order(order_id:int, db: SessionLocal = Depends(get_db), current: User = Depends(get_current_user)):
    o = db.query(Order).filter(Order.id==order_id).first()
    if not o: raise HTTPException(status_code=404, detail="Order not found")
    # only buyer or listing owner can mark completed
    listing = db.query(Listing).filter(Listing.id==o.listing_id).first()
    if current.id not in (o.buyer_id, listing.owner_id):
        raise HTTPException(status_code=403, detail="Not allowed")
    o.status = "completed"
    listing.status = "sold"
    db.add(o); db.add(listing); db.commit()
    return {"message":"order completed"}

# ---------------- CHAT ----------------
@app.post("/chats")
def start_chat(listing_id: int = Form(...), other_user_id: int = Form(...), db: SessionLocal = Depends(get_db), current:User = Depends(get_current_user)):
    # find existing chat
    chat = db.query(Chat).filter(Chat.listing_id==listing_id, ((Chat.user1==current.id)&(Chat.user2==other_user_id)) | ((Chat.user2==current.id)&(Chat.user1==other_user_id))).first()
    if chat:
        return {"chat_id": chat.id}
    c = Chat(listing_id=listing_id, user1=current.id, user2=other_user_id)
    db.add(c); db.commit(); db.refresh(c)
    return {"chat_id": c.id}

@app.post("/chats/{chat_id}/messages")
def send_message(chat_id:int, text: Optional[str] = Form(None), image: Optional[UploadFile] = File(None), db: SessionLocal = Depends(get_db), current:User = Depends(get_current_user)):
    ch = db.query(Chat).filter(Chat.id==chat_id).first()
    if not ch: raise HTTPException(status_code=404, detail="Chat not found")
    if current.id not in (ch.user1, ch.user2):
        raise HTTPException(status_code=403, detail="Not participant")
    img_path = None
    if image:
        p, t = save_upload(image)
        img_path = p
    m = Message(chat_id=chat_id, sender_id=current.id, text=text or "", image=img_path, created_at=datetime.utcnow())
    db.add(m); db.commit(); db.refresh(m)
    return {"message_id": m.id}

@app.get("/chats/{chat_id}/messages")
def get_messages(chat_id:int, db: SessionLocal = Depends(get_db), current:User = Depends(get_current_user)):
    ch = db.query(Chat).filter(Chat.id==chat_id).first()
    if not ch: raise HTTPException(status_code=404, detail="Chat not found")
    if current.id not in (ch.user1, ch.user2):
        raise HTTPException(status_code=403, detail="Not participant")
    msgs = db.query(Message).filter(Message.chat_id==chat_id).order_by(Message.created_at.asc()).all()
    return [{"id":m.id, "sender":m.sender_id, "text":m.text, "image":m.image, "created_at":m.created_at} for m in msgs]

# ---------------- REVIEWS ----------------
@app.post("/reviews")
def leave_review(listing_id:int = Form(...), rating:int = Form(...), comment:Optional[str] = Form(None), db: SessionLocal = Depends(get_db), current:User = Depends(get_current_user)):
    # ensure order completed check is omitted for simplicity
    r = Review(listing_id=listing_id, author_id=current.id, rating=rating, comment=comment, created_at=datetime.utcnow())
    db.add(r); db.commit(); db.refresh(r)
    return {"message":"review added", "id": r.id}

@app.get("/reviews/{listing_id}")
def get_reviews(listing_id:int, db: SessionLocal = Depends(get_db)):
    revs = db.query(Review).filter(Review.listing_id==listing_id).all()
    return [{"id":r.id, "author": r.author_id, "rating": r.rating, "comment": r.comment, "created_at": r.created_at} for r in revs]

# ---------------- ADMIN (basic) ----------------
@app.get("/admin/users")
def admin_list_users(db: SessionLocal = Depends(get_db), current:User = Depends(get_current_user)):
    if not current.is_admin:
        raise HTTPException(status_code=403, detail="admin only")
    users = db.query(User).all()
    return [{"id":u.id, "name": u.name, "email": u.email, "phone": u.phone, "verified": u.verified} for u in users]

# ---------------- HEALTH ----------------
@app.get("/health")
def health():
    return {"status":"ok"}