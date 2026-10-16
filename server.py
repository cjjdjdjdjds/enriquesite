# ============================================================
# Enrique RP — сервер (SQLite, работает везде)
# ============================================================

import os
import random
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel, Field
from sqlalchemy import Column, Integer, String, BigInteger, DateTime, create_engine, select, update
from sqlalchemy.orm import declarative_base, Session, sessionmaker

# ============================================================
# НАСТРОЙКИ
# ============================================================

SECRET_KEY = "enrique-rp-secret-key-change-me"
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 72

DB_FILE = "enrique.db"
DB_URL = f"sqlite:///{DB_FILE}"

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ============================================================
# МОДЕЛИ
# ============================================================

class Account(Base):
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True, index=True)
    Name = Column(String(24), unique=True, nullable=False)
    pPass = Column(String(129), nullable=False)
    pLvl = Column(Integer, default=1)
    pAdm = Column(Integer, default=0)
    pAdmWarns = Column(Integer, default=0)
    pLeaderWarns = Column(Integer, default=0)
    pVip = Column(Integer, default=0)
    pVipDays = Column(Integer, default=0)
    pExp = Column(Integer, default=0)
    pCash = Column(BigInteger, default=1000)
    pBank = Column(BigInteger, default=0)
    pKills = Column(Integer, default=0)
    pLeader = Column(Integer, default=0)
    pRank = Column(Integer, default=0)
    pMember = Column(Integer, default=0)
    pWarns = Column(Integer, default=0)
    pZakonp = Column(Integer, default=0)


class MinigameLog(Base):
    __tablename__ = "minigame_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, index=True)
    game = Column(String(32))
    bet = Column(BigInteger)
    win = Column(BigInteger)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================
# ПАРОЛИ И ТОКЕНЫ
# ============================================================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_token(user_id: int, name: str) -> str:
    payload = {
        "sub": str(user_id),
        "name": name,
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


security = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> Account:
    if not credentials:
        raise HTTPException(status_code=401, detail="Нет токена")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
    except (JWTError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Неверный токен")

    user = db.query(Account).filter(Account.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Игрок не найден")
    return user


# ============================================================
# СХЕМЫ
# ============================================================

class RegisterRequest(BaseModel):
    name: str = Field(min_length=3, max_length=20)
    password: str = Field(min_length=6, max_length=64)


class LoginRequest(BaseModel):
    name: str
    password: str


class BetRequest(BaseModel):
    bet: int = Field(gt=0)
    choice: Optional[str] = None


# ============================================================
# ПРИЛОЖЕНИЕ
# ============================================================

app = FastAPI(title="Enrique RP", version="1.0")


@app.get("/", response_class=HTMLResponse)
def root():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse("<h1>index.html не найден</h1>", status_code=500)


# ---------- АВТОРИЗАЦИЯ ----------

@app.post("/api/register")
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    exists = db.query(Account).filter(Account.Name == data.name).first()
    if exists:
        raise HTTPException(status_code=400, detail="Имя уже занято")

    new_acc = Account(
        Name=data.name,
        pPass=hash_password(data.password),
        pLvl=1,
        pCash=1000,
        pBank=0,
    )
    db.add(new_acc)
    db.commit()
    db.refresh(new_acc)

    token = create_token(new_acc.id, new_acc.Name)
    return {"ok": True, "token": token, "name": new_acc.Name}


@app.post("/api/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(Account).filter(Account.Name == data.name).first()
    if not user or not verify_password(data.password, user.pPass):
        raise HTTPException(status_code=400, detail="Неверное имя или пароль")

    token = create_token(user.id, user.Name)
    return {"ok": True, "token": token, "name": user.Name}


# ---------- ПРОФИЛЬ ----------

def serialize(user: Account) -> dict:
    return {
        "id": user.id,
        "name": user.Name,
        "level": user.pLvl or 0,
        "exp": user.pExp or 0,
        "cash": user.pCash or 0,
        "bank": user.pBank or 0,
        "total": (user.pCash or 0) + (user.pBank or 0),
        "kills": user.pKills or 0,
        "vip": user.pVip or 0,
        "vip_days": user.pVipDays or 0,
        "admin": user.pAdm or 0,
        "rank": user.pRank or 0,
        "leader": user.pLeader or 0,
        "member": user.pMember or 0,
        "warns": user.pWarns or 0,
        "adm_warns": user.pAdmWarns or 0,
        "leader_warns": user.pLeaderWarns or 0,
        "zakonp": user.pZakonp or 0,
    }


@app.get("/api/me")
def me(user: Account = Depends(get_current_user)):
    return serialize(user)


@app.get("/api/leaderboard")
def leaderboard(db: Session = Depends(get_db)):
    users = db.query(Account).order_by(Account.pCash.desc()).limit(10).all()
    return [{"name": u.Name, "cash": u.pCash or 0, "level": u.pLvl or 0} for u in users]


# ---------- МИНИ-ИГРЫ ----------

def update_cash(db: Session, user_id: int, new_cash: int):
    db.query(Account).filter(Account.id == user_id).update({"pCash": new_cash})
    db.commit()


def log_game(db: Session, user_id: int, game: str, bet: int, win: int):
    db.add(MinigameLog(user_id=user_id, game=game, bet=bet, win=win))
    db.commit()


@app.post("/api/game/dice")
def game_dice(data: BetRequest, user: Account = Depends(get_current_user), db: Session = Depends(get_db)):
    cash = user.pCash or 0
    if cash < data.bet:
        raise HTTPException(status_code=400, detail="Недостаточно денег")
    if data.bet > max(cash // 2, 100):
        raise HTTPException(status_code=400, detail="Максимум — половина баланса")

    d1 = random.randint(1, 6)
    d2 = random.randint(1, 6)
    total = d1 + d2

    if total >= 8:
        win = data.bet * 2
        msg = f"Выпало {d1}+{d2}={total}. Победа ×2!"
    elif total >= 5:
        win = data.bet
        msg = f"Выпало {d1}+{d2}={total}. Возврат ставки."
    else:
        win = 0
        msg = f"Выпало {d1}+{d2}={total}. Проигрыш."

    new_cash = cash - data.bet + win
    update_cash(db, user.id, new_cash)
    log_game(db, user.id, "dice", data.bet, win)
    return {"ok": True, "dice": [d1, d2], "total": total, "win": win, "cash": new_cash, "message": msg}


@app.post("/api/game/coin")
def game_coin(data: BetRequest, user: Account = Depends(get_current_user), db: Session = Depends(get_db)):
    if data.choice not in ("heads", "tails"):
        raise HTTPException(status_code=400, detail="Выбери heads или tails")

    cash = user.pCash or 0
    if cash < data.bet:
        raise HTTPException(status_code=400, detail="Недостаточно денег")
    if data.bet > max(cash // 2, 100):
        raise HTTPException(status_code=400, detail="Максимум — половина баланса")

    result = random.choice(["heads", "tails"])
    if result == data.choice:
        win = data.bet * 2
        msg = f"Выпало: {'орёл' if result == 'heads' else 'решка'}. Победа ×2!"
    else:
        win = 0
        msg = f"Выпало: {'орёл' if result == 'heads' else 'решка'}. Проигрыш."

    new_cash = cash - data.bet + win
    update_cash(db, user.id, new_cash)
    log_game(db, user.id, "coin", data.bet, win)
    return {"ok": True, "result": result, "win": win, "cash": new_cash, "message": msg}


@app.post("/api/game/guess")
def game_guess(data: BetRequest, user: Account = Depends(get_current_user), db: Session = Depends(get_db)):
    if not data.choice or not data.choice.lstrip("-").isdigit():
        raise HTTPException(status_code=400, detail="Выбери число 1–10")

    guess = int(data.choice)
    if guess < 1 or guess > 10:
        raise HTTPException(status_code=400, detail="Число от 1 до 10")

    cash = user.pCash or 0
    if cash < data.bet:
        raise HTTPException(status_code=400, detail="Недостаточно денег")
    if data.bet > max(cash // 2, 100):
        raise HTTPException(status_code=400, detail="Максимум — половина баланса")

    secret = random.randint(1, 10)
    if guess == secret:
        win = data.bet * 5
        msg = f"Загадано {secret}. Угадал! ×5"
    else:
        win = 0
        msg = f"Загадано {secret}. Не угадал."

    new_cash = cash - data.bet + win
    update_cash(db, user.id, new_cash)
    log_game(db, user.id, "guess", data.bet, win)
    return {"ok": True, "secret": secret, "win": win, "cash": new_cash, "message": msg}


@app.post("/api/game/roulette")
def game_roulette(data: BetRequest, user: Account = Depends(get_current_user), db: Session = Depends(get_db)):
    if data.choice not in ("red", "black", "zero"):
        raise HTTPException(status_code=400, detail="Выбери red, black или zero")

    cash = user.pCash or 0
    if cash < data.bet:
        raise HTTPException(status_code=400, detail="Недостаточно денег")
    if data.bet > max(cash // 2, 100):
        raise HTTPException(status_code=400, detail="Максимум — половина баланса")

    roll = random.randint(0, 36)
    if roll == 0:
        result = "zero"
    elif roll % 2 == 0:
        result = "black"
    else:
        result = "red"

    if result == data.choice:
        multiplier = 14 if result == "zero" else 2
        win = data.bet * multiplier
        msg = f"Выпало {roll} ({result}). Победа ×{multiplier}!"
    else:
        win = 0
        msg = f"Выпало {roll} ({result}). Проигрыш."

    new_cash = cash - data.bet + win
    update_cash(db, user.id, new_cash)
    log_game(db, user.id, "roulette", data.bet, win)
    return {"ok": True, "roll": roll, "result": result, "win": win, "cash": new_cash, "message": msg}


# ============================================================
# ЗАПУСК
# ============================================================

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("server:app", host="0.0.0.0", port=port)
