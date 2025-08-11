class Animal:
    def __init__(self, name, species):
        self.name = name
        self.species = species

    def make_sound(self):
        print("Some generic sound")


animal1 = Animal("GenericAnimal", "Unknown")
animal1.make_sound()


class Dog(Animal):
    def make_sound(self):
        print("Woof!")


class Cat(Animal):
    def make_sound(self):
        print("Meow!")


dog1 = Dog("Tommy", "Dog")
cat1 = Cat("Kitty", "Cat")
dog1.make_sound()
cat1.make_sound()
