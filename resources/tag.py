from db import db
from flask_smorest import Blueprint,abort
from  flask.views import MethodView
from models import TagModel,StoreModel,ItemModel
from schemas import TagsSchema,ItemAndTagSchema


blp= Blueprint('Tags',__name__,description='Operatioins on Tags')


@blp.route('/store/<string:store_id>/tag')
class TagsInStore(MethodView):
    
    @blp.response(200,TagsSchema(many=True))
    def get(self,store_id):
        try:
            store=StoreModel.query.get_or_404(store_id)
            return store.tags.all()
        except:
            abort(404,message='we cant find store id')

    @blp.arguments(TagsSchema)
    @blp.response(201,TagsSchema)
    def post(self,tagData,store_id):

        tag=TagModel(**tagData,store_id=store_id)
        try:
            db.session.add(tag)
            db.session.commit()
            return tag
        except:
            abort(500,message='error happen while saving a tag')


@blp.route('/tag/<string:tag_id>')
class Tag(MethodView):
    
    @blp.response(200,TagsSchema)
    def get(self,tag_id):
        tag= TagModel.query.get_or_404(tag_id)
        return tag

    @blp.response(202,description='delete tag if not item linked',example={'message':'tag deleted'})
    @blp.response(404,description='tag not found')
    @blp.response(400,description='can not delete tag linked to item')
    def delete(self,tag_id):
        tag=TagModel.query.get_or_404(tag_id)

        if not tag.items:
            db.session.delete(tag)
            db.session.commit()
            return {'message': 'tag is deleted'}

        abort(400,message='can not delete tag linked to item')


@blp.route('/item/<string:item_id>/tag/<string:tag_id>')
class ItemLinkTag(MethodView):
     
     @blp.response(201,TagsSchema)
     def post(self,item_id,tag_id):
        item=ItemModel.query.get_or_404(item_id)
        tag=TagModel.query.get_or_404(tag_id)
        try:
            item.tags.append(tag)
            db.session.add(item)
            db.session.commit()
            return tag
        except:
            abort(500,message="error occured while linking item and tag")

     @blp.response(201,ItemAndTagSchema)
     def delete(self,item_id,tag_id):
        item=ItemModel.query.get_or_404(item_id)
        tag=TagModel.query.get_or_404(tag_id)
        try:
            item.tags.remove(tag)
            db.session.add(item)
            db.session.commit()
            return {'message':'an item is removed from tag','item':item,'tag':tag}
        except:
            abort(500,message="error occured while unlinking item and tag")