from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///itemcatalogwithusers.db')
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

#User01 = User(name="Ankush Sankhe", email="ankushsankhe123@gmail.com", 
#             picture='')
#session.add(User01)
#session.commit()

# Create dummy user
User1 = User(name="Ankush Sankhe", email="ankushsankhe@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()


# Item for Cricket
category1 = Category(user_id=1, name="Cricket")

session.add(category1)
session.commit()

item1 = Item(user_id=1, name="Bat", description="A wooden block used by the batsmen to hit the ball",
              category=category1)

session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Ball", description="A red ball used by the bowler to bowl",
              category=category1)

session.add(item2)
session.commit()

item3 = Item(user_id=1, name="Gloves", description="A protective cover for hands used by the batsmen while batting",
              category=category1)

session.add(item3)
session.commit()

item4 = Item(user_id=1, name="Pads", description="A protective cover for legs used by the batsmen while batting",
              category=category1)

session.add(item4)
session.commit()

item5 = Item(user_id=1, name="Thigh Guard", description="A protective cover for thighs used by the batsmen while batting",
              category=category1)

session.add(item5)
session.commit()

item6 = Item(user_id=1, name="Helmet", description="A protective cover for head used by the batsmen while batting",
              category=category1)

session.add(item6)
session.commit()

item7 = Item(user_id=1, name="WicketKeeperGloves", description="A protective cover for hands used by the wicketkeeper while fielding",
              category=category1)

session.add(item7)
session.commit()


# Item for Hockey
category2 = Category(user_id=1, name="Hockey")

session.add(category2)
session.commit()

item1 = Item(user_id=1, name="Hockey Stick", description="A wooden stick used by the players to hit the ball",
              category=category2)

session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Ball", description="A ball used for playing",
              category=category2)

session.add(item2)
session.commit()

item3 = Item(user_id=1, name="Helmet", description="A protective guard for head used by goalkeeper",
              category=category2)

session.add(item3)
session.commit()

item4 = Item(user_id=1, name="Gloves", description="A protective guard for hands used by goalkeeper",
              category=category2)

session.add(item4)
session.commit()

item5 = Item(user_id=1, name="Pads", description="A protective guard for legs used by goalkeeper",
              category=category2)

session.add(item5)
session.commit()


print "added items in the catalog!"