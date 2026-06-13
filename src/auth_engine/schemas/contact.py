from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class ContactLeadCreate(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    email: EmailStr
    phone: str | None = Field(None, max_length=50)
    job_title: str | None = Field(None, max_length=200)
    company: str = Field(..., min_length=1, max_length=200)
    company_size: str | None = Field(None, max_length=50)
    country: str | None = Field(None, max_length=100)
    mau: str | None = Field(None, max_length=50)
    interest: str | None = Field(None, max_length=200)
    message: str | None = Field(None, max_length=5000)
    consent: bool


class ContactLead(ContactLeadCreate):
    id: str
    created_at: datetime
    source: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
