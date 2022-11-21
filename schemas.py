from marshmallow import fields,Schema

class PlainItemSchema(Schema):

    item_id=fields.Int(dump_only=True)
    name=fields.Str(required=True)
    price=fields.Float(required=True)

class PlainStoreSchema(Schema):
    store_id=fields.Int(dump_only=True)
    name=fields.Str(required=True)

class PlainTagSchema(Schema):
    tag_id=fields.Int(dump_only=True)
    name=fields.Str(required=True)

class ItemSchema(PlainItemSchema):
    store_id=fields.Int(required=True)
    store=fields.Nested(PlainStoreSchema(),dump_only=True)
    tags=fields.List(fields.Nested(PlainTagSchema()),dump_only=True)

class ItemUpdateSchema(Schema):
    name=fields.Str()
    price=fields.Float()

class StoreSchema(PlainStoreSchema):
    Items=fields.List(fields.Nested(PlainItemSchema()),dump_only=True)
    tags=fields.List(fields.Nested(PlainTagSchema()),dump_only=True)

class TagsSchema(PlainTagSchema):
    store_id=fields.Int(load_only=True)
    store=fields.Nested(PlainStoreSchema(),dump_only=True)
    items=fields.List(fields.Nested(PlainItemSchema()),dump_only=True)

class ItemAndTagSchema(Schema):
    message = fields.Str()
    item = fields.Nested(ItemSchema)
    tag = fields.Nested(TagsSchema)

class UserSchema(Schema):
    user_id=fields.Int(dump_only=True)
    username=fields.Str(required=True)
    password=fields.Str(required=True,load_only=True)
    