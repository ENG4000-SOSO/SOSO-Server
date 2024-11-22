from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional


class User(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password_hash: str = Field(..., max_length=255)
    

    
   


