from db import db

class ItemModel(db.Model):
    
    __tablename__='items'

    item_id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(80),nullable=False)
    price=db.Column(db.Float(precision=2), nullable=False)
    store_id=db.Column(db.Integer,db.ForeignKey("stores.store_id"),nullable=False)

    store=db.relationship("StoreModel",back_populates="items")
    tags=db.relationship('TagModel',back_populates='items',secondary='item_tag')

