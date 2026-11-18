import os
import oc.datastore

mongodburl = os.getenv('MONGODB_URL') 
databasename = 'applications'
image_collection_name = 'image'
datastore = oc.datastore.ODMongoDatastoreClient(mongodburl, 'directConnection=true', databasename)
client = datastore.createclient(databasename)

collection = client[databasename][image_collection_name]
print( f"collection type is {type(collection)}" )
# collection.insert_one( { 'counter':1 } )
print( list( collection.find() ))
