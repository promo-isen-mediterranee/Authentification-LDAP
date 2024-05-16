from routes import *

with app.app_context():
    logger.info('App started')
    db.create_all()
