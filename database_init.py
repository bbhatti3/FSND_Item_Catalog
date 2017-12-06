from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Category, Item, User

engine = create_engine('sqlite:///itemCatalogApp.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


categories = [
    ['football equipment',
        [{'name': 'helmet',
          'description': 'Head protection made from light-weight'
          'Polycarbonate material, designed to offer maximum '
          'protection for incredible impact force, '
          'especially in helmet-to-helmet contact.'},
         {'name': 'shoulder pads',
          'description': 'Designed to protect the upper '
          'body from the rigors of full contact football, '
          'shoulder pads become the first line of defense '
          'when barreling into a tackle.'},
         {'name': 'pants',
          'description': 'Padding to protect the lower '
          'half of the body, and housing and stabilize your '
          'knee pads, but they also keep you safe from serious '
          'injuries and abrasions that can happen during almost any play.'},
         {'name': 'facemask',
          'description': 'Facemasks are combined with the helmet to '
          'protect your eyes, nose, mouth, teeth, jaw, and chin'}]],
    ['basketball equipment',
        [{'name': 'basketball',
          'description': 'A basketball is a spherical ball used in '
          'basketball games. Basketballs typically range in size from '
          'very small promotional items only a few inches in diameter to '
          'extra large balls nearly a foot in diameter used in '
          'training exercises.'}]],
    ['baseball equipment',
        [{'name': 'bat',
          'description': 'A baseball bat is a smooth wooden or metal '
          'club used in the sport of baseball to hit the ball after it '
          'is thrown by the pitcher.'},
         {'name': 'gloves',
          'description': 'A baseball glove or mitt is a large leather glove '
          'worn by baseball players of the defending team, which assists '
          'players in catching and fielding balls hit by a batter or '
          'thrown by a teammate.'}]],
    ['volleyball equipment',
        [{'name': 'volleyball',
          'description': 'The standard volleyball is made of '
          'leather or synthetic leather, weighs between 9 and 10 '
          'ounces and has a circumference of 25.6 to 26.4 inches'}]]
]

current_user = User(name="MCHammer", email="cant@this.com")
session.add(current_user)
session.commit()

for category in categories:
    current_category = Category(name=category[0], user=current_user)
    session.add(current_category)
    session.commit()

    for item in category[1]:
        current_item = Item(name=item['name'],
                            description=item['description'],
                            category=current_category,
                            user=current_user)
        session.add(current_item)
        session.commit()
