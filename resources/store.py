from flask import request
from flask.views import MethodView
from flask_smorest import Blueprint, abort
from models import StoreModel
from schemas import StoreSchema,PlainStoreSchema
from db import db
from flask_jwt_extended import jwt_required,get_jwt


blp=Blueprint('store',__name__,description='Operations On Stores ')

@blp.route('/store/<string:store_id>')
class Store(MethodView):

    @jwt_required()
    @blp.response(200,StoreSchema)
    def get(self,store_id):
        store=StoreModel.query.get_or_404(store_id)
        return store

    # only fresh token can access this endpoint
    @jwt_required(fresh=True)
    @blp.arguments(PlainStoreSchema)
    @blp.response(201,StoreSchema)
    def put(self,storeData,store_id):
        store=StoreModel.query.get_or_404(store_id)
        try:
            
            store.name=storeData['name']
            db.session.add(store)
            db.session.commit()
            return store
        except:
            abort(500,message='something went wrong while updating store')

    @jwt_required(fresh=True)
    def delete(self,store_id):

        jwt=get_jwt()
        if not jwt.get('is_admin'):
            abort(401,message='admin prevelage is required')

        store=StoreModel.query.get_or_404(store_id)
        try:
            db.session.delete(store)
            db.session.commit()
            return {'message':'store is successful deleted'}
        except:
            abort(500,message='something went wrong while deleting store')



@blp.route('/store')
class StoreList(MethodView):
    
    # this endpoint can be accessed by (access or refresh) token or  fresh token
    @jwt_required(verify_type=False,)
    @blp.response(200,StoreSchema(many=True))
    def get(self):
        return StoreModel.query.all()

    # only jwt token is required
    @jwt_required()
    @blp.arguments(PlainStoreSchema)
    @blp.response(201,StoreSchema)
    def post(self,storeItem):
        store=StoreModel(**storeItem)
        try:
            db.session.add(store)
            db.session.commit()
            return store
        except:
            return abort(500,message='something went wrong while saving store!')