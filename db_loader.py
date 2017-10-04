from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db_setup import Activity, Base, ActivityItem, User

engine = create_engine('sqlite:///activitiesapp.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# Items for Air Rifle Shooting
activity1 = Activity(user_id=1, name="Air Rifle Shooting", picture="static/air-rifle.jpg")

session.add(activity1)
session.commit()

AItem1 = ActivityItem(user_id=1, name="Air Rifle", description="Ermm... an Air Rifle",
                     price="$97.50", activity=activity1)

session.add(AItem1)
session.commit()


AItem2 = ActivityItem(user_id=1, name="Pellets", description="Little cup like projectile that goes in your air rifle",
                     price="$9.99 x 50", activity=activity1)

session.add(AItem2)
session.commit()

AItem3 = ActivityItem(user_id=1, name="Target", description="The thingie you shoot at...",
                     price="$8.50 x 10", activity=activity1)

session.add(AItem3)
session.commit()

AItem4 = ActivityItem(user_id=1, name="Eye protection", description="Basically, goggles to protect your eyes from stray pellets...",
                     price="$11.99", activity=activity1)

session.add(AItem4)
session.commit()

print "added activity items!"
