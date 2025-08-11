class Shape:
    def area(self):
        print("Area not defined")
class Circle(Shape):
    def __init__(self,radius):
        self.radius=radius
    def area(self):    
        area1=3.14*(self.radius**2)
        print(f"Area of circle = {area1}")
class Rectangle(Shape):
    def __init__(self,length,breadth):
        self.length=length
        self.breadth=breadth
    def area(self):
        area2=self.length*self.breadth
        print(f"Area of rectagle = {area2}")
shape=Shape()
shape.area()
circle=Circle(10)
circle.area()
rectangle=Rectangle(12,13)
rectangle.area()