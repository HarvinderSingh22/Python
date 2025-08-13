class Employee:
    def __init__(self, name, employee_id, department):
        self.name = name
        self.employee_id = employee_id
        self.department = department

    def display_details(self):
        print(f"Name: {self.name}")
        print(f"Employee_id: {self.employee_id}")
        print(f"Department: {self.department}")


class Manager(Employee):
    def __init__(self, name, employee_id, department, team_size):
        super().__init__(name, employee_id, department)
        self.team_size = team_size

    def display_details(self):
        return super().display_details()
        print(f"Team size: {self.team_size}")


class Developer(Employee):
    def __init__(self, name, employee_id, department, programming_language):
        super().__init__(name, employee_id, department)
        self.programming_language = programming_language

    def display_details(self):
        return super().display_details()
        print(f"Programming language: {self.programming_language}")


manager1 = Manager("Asif", "Asif1", "Sales", 11)
developer1 = Developer("Harry", "Har001", "IT", "Python")

print("Manager Details")
manager1.display_details()

print(f"\nDeveloper Details")
developer1.display_details()
