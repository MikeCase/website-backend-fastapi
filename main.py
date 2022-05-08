import jwt
from typing import List, Optional

from passlib.hash import bcrypt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise import fields
from tortoise.contrib.fastapi import register_tortoise
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.models import Model
from pydantic import BaseModel

JWT_SECRET = 'MyJWTSecret'

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

class User(Model):
    id = fields.IntField(pk=True)
    email = fields.CharField(255, unique=True)
    password_hash = fields.CharField(128)

    def verify_pwd(self, pwd):
        return bcrypt.verify(pwd, self.password_hash)

User_Pydantic = pydantic_model_creator(User, name='User')
UserIn_Pydantic = pydantic_model_creator(User, name='UserIn', exclude_readonly=True)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = await User.get(id=payload.get('id'))
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid username or password'
        )

    return await User_Pydantic.from_tortoise_orm(user)


@app.post('/users', response_model=User_Pydantic)
async def create_user(user: UserIn_Pydantic):
    user_obj = User(email=user.email, password_hash=bcrypt.hash(user.password_hash))
    await user_obj.save()
    return await User_Pydantic.from_tortoise_orm(user_obj)

@app.get('/users/me', response_model=User_Pydantic)
async def get_user(user: User_Pydantic = Depends(get_current_user)):
    return user

async def auth_user(email: str, pwd: str):
    user = await User.get(email=email)
    if not user:
        return False
    if not user.verify_pwd(pwd):
        return False
    return user

@app.post('/token')
async def gen_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await auth_user(form_data.username, form_data.password)
    if not user:
        return {'Error': 'Failed to login!'}

    user_obj = await User_Pydantic.from_tortoise_orm(user)
    token = jwt.encode(user_obj.dict(), JWT_SECRET)

    return {'access_token': token, 'token_type': 'bearer'}

@app.get('/')
async def index(token: str = Depends(oauth2_scheme)):
    return {'the_token': token}

skills_db = [
    {'name': 'Python'},
    {'name': 'PHP'},
    {'name': 'JavaScript'},
]

class Skill(BaseModel):
    name: str

@app.get("/skills")
async def skills():
    return skills_db

@app.post("/skills")
async def create_skill(skill: Skill):
    skills_db.append(skill)
    return skill

register_tortoise(
    app,
    db_url='sqlite://db.sql3',
    modules={'models': ['main']},
    generate_schemas=True,
    add_exception_handlers=True

)