from db import db

class ItemTag(db.Model):
    __tablename__='item_tag'

    id=db.Column(db.Integer,primary_key=True)
    item_id=db.Column(db.Integer,db.ForeignKey('items.item_id'))
    tag_id=db.Column(db.Integer,db.ForeignKey('tags.tag_id'))