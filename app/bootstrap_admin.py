"""Explicitly set admin password on an existing MySQL/SQLite database."""
import argparse, getpass
from sqlalchemy import select
from .db import make_engine, initialize
from .models import Role, User
from .security import hash_password
from sqlalchemy.orm import Session

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--email',required=True)
    parser.add_argument('--name',default='Project Admin')
    args=parser.parse_args()
    password=getpass.getpass('Choose admin password (10+ chars): ')
    if len(password)<10: raise SystemExit('Password too short')
    engine=make_engine();initialize(engine)
    with Session(engine) as db:
        role=db.scalar(select(Role).where(Role.role_name=='ADMIN'))
        if not role: role=Role(role_name='ADMIN');db.add(role);db.flush()
        user=db.scalar(select(User).where(User.email==args.email.strip().lower()))
        if user:
            print('Updating password of existing user:',user.email)
            user.password_hash=hash_password(password);user.role_id=role.role_id
        else:
            db.add(User(email=args.email.lower(),name=args.name,password_hash=hash_password(password),role_id=role.role_id))
        db.commit()
    print('Admin credentials configured.')
if __name__=='__main__':main()
