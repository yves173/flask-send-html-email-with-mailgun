from flask import request
from flask_smorest import Blueprint, abort
from flask.views import MethodView
from models import ItemModel
from schemas import ItemSchema,ItemUpdateSchema,PlainItemSchema
from db import db


blp=Blueprint('items',__name__,description='Operations on Item')

@blp.route("/item/<string:item_id>")
class Item(MethodView):

    @blp.response(200,ItemSchema)
    def get(self,item_id):
        item=ItemModel.query.get_or_404(item_id)
        return item

    @blp.arguments(ItemUpdateSchema)
    @blp.response(201,ItemSchema)
    def put(self,itemData,item_id):
        item=ItemModel.query.get_or_404(item_id)
        try:
            item.name=itemData.get('name') or item.name
            item.price=itemData.get('price') or item.price
            db.session.add(item)
            db.session.commit()
            return item
        except:
            abort(500,message='something went while updating item')

    def delete(self,item_id):
        item=ItemModel.query.get_or_404(item_id)
        try:
            db.session.delete(item)
            db.session.commit()
            return {'message':'item is successfully deleted'}
        except:
            abort(500,message='something went wrong while deleteing item')



@blp.route('/item')
class ItemList(MethodView):

    @blp.response(200,ItemSchema(many=True))
    def get(self):
        return ItemModel.query.all()

    @blp.arguments(ItemSchema)
    @blp.response(201,ItemSchema)
    def post(self,itemData):
        item=ItemModel(**itemData)
        try:
            db.session.add(item)
            db.session.commit()
            return item
        except:
            abort(500,message='an error occured while saving Item!')