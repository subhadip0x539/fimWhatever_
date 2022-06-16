from dictdiffer import diff
from mongoengine.queryset.visitor import Q

def compare_db(data, db):
    save = False
    file = db.objects(file=data['file'])
    hash = db.objects(hash=data['hash'])

    doc = db.objects(Q(file=data['file']))
    if not doc :
        save=True
    
    return save

def compare_db_gin(data, db):
    save = False
    doc = db.objects(Q(file=data['file']) & Q(file_id=data['file_id']))
    
    if not doc :
        save = True

    return save

def compare_db_kin(data, db):
    save = False
    doc = db.objects(Q(file=data['file']) & Q(hash=data['hash']) &Q(file_id=data['file_id'])& Q(status=data['status']))
    # & Q(modifydate=data['modifydate'])
    
    if not doc :
        save = True
    
    return save    

def compare_hash(hash_fs, hash_db):
    if hash_fs == hash_db:
        return 2
    else:
        return 3



def drop_collection(arr):
    for db in arr:
        db.delete()        

def set_analyticsTozero(anal):
    anal.update(**{'baseline': 0, 'alerts': 0, 'scans': 0, 'encs': 0})   
