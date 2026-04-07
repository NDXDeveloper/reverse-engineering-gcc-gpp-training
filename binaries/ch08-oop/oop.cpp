/**
 * Reverse Engineering Training — Chapter 08: Object-oriented C++ application
 *
 * This program showcases a small vehicle management system
 * using polymorphism, simple inheritance and multi-level inheritance.
 *
 * Class hierarchy:
 *
 *   Vehicle              (root class, concrete)
 *   ├── Car              (simple inheritance)
 *   │   └── ElectricCar  (two-level inheritance)
 *   └── Motorcycle       (simple inheritance)
 *
 * C++ concepts illustrated (visible in the binary):
 *   - vtables and vptr (virtual methods)
 *   - RTTI (__class_type_info, __si_class_type_info)
 *   - Itanium ABI name mangling
 *   - Chained constructors (parent constructor call)
 *   - Virtual destructors (D0 deleting, D1 complete)
 *   - Non-virtual methods (direct call, no vtable slot)
 *   - std::string in memory (SSO, libstdc++)
 *   - Polymorphic dispatch via array of base pointers
 *
 * MIT License — Strictly educational use.
 */

#include <iostream>
#include <string>
#include <vector>

// ============================================================================
// Base class: Vehicle
// ============================================================================

class Vehicle {
public:
    Vehicle(const std::string& name, int fuel_level)
        : name_(name), fuel_level_(fuel_level)
    {
    }

    virtual ~Vehicle()
    {
        std::cout << "Destroying vehicle: " << name_ << std::endl;
    }

    // Virtual method — overridden by each derived class.
    // Slot [2] in the vtable (after the two destructors D1/D0).
    virtual void start()
    {
        std::cout << "Starting generic vehicle: " << name_ << std::endl;
        fuel_level_ -= 1;
    }

    // Virtual method — inherited without override by the entire hierarchy.
    // Slot [3] in the vtable. The pointer remains identical in all vtables.
    virtual void display_info() const
    {
        std::cout << "[Vehicle] name=" << name_
                  << " fuel=" << fuel_level_ << std::endl;
    }

    // NON-virtual method — direct call (immediate CALL), no vtable slot.
    int get_fuel_level() const
    {
        return fuel_level_;
    }

protected:
    std::string name_;       // offset 0x08 (after vptr), sizeof = 32 (libstdc++ x86-64)
    int         fuel_level_; // offset 0x28
    // 4 bytes padding → sizeof(Vehicle) = 0x30 (48)
};

// ============================================================================
// Derived class: Car (inherits from Vehicle)
// ============================================================================

class Car : public Vehicle {
public:
    Car(const std::string& name, int fuel_level, int num_doors)
        : Vehicle(name, fuel_level), num_doors_(num_doors)
    {
    }

    ~Car() override
    {
        std::cout << "Destroying car: " << name_
                  << " (" << num_doors_ << " doors)" << std::endl;
    }

    // Override of Vehicle::start() — slot [2] of the Car vtable
    // points to Car::start() instead of Vehicle::start().
    void start() override
    {
        std::cout << "Starting car: " << name_
                  << " (" << num_doors_ << " doors)" << std::endl;
        fuel_level_ -= 2;
    }

    // display_info() is NOT overridden: slot [3] of the Car vtable
    // contains the same pointer as Vehicle::display_info().

    // NON-virtual method specific to Car.
    void open_trunk() const
    {
        std::cout << name_ << ": trunk opened." << std::endl;
    }

private:
    int num_doors_; // offset 0x30
    // 4 bytes padding → sizeof(Car) = 0x38 (56)
};

// ============================================================================
// Derived class: Motorcycle (inherits from Vehicle)
// ============================================================================

class Motorcycle : public Vehicle {
public:
    Motorcycle(const std::string& name, int fuel_level, bool has_sidecar)
        : Vehicle(name, fuel_level), has_sidecar_(has_sidecar)
    {
    }

    ~Motorcycle() override
    {
        std::cout << "Destroying motorcycle: " << name_ << std::endl;
    }

    // Override of Vehicle::start().
    void start() override
    {
        std::cout << "Kick-starting motorcycle: " << name_;
        if (has_sidecar_) {
            std::cout << " (with sidecar)";
        }
        std::cout << std::endl;
        fuel_level_ -= 1;
    }

    // display_info() inherited without override, same as Car.

private:
    bool has_sidecar_; // offset 0x30, 1 byte + 7 bytes padding
    // sizeof(Motorcycle) = 0x38 (56)
};

// ============================================================================
// Derived class of Car: ElectricCar (two-level inheritance)
// ============================================================================

class ElectricCar : public Car {
public:
    ElectricCar(const std::string& name, int fuel_level, int num_doors,
                int battery_kw)
        : Car(name, fuel_level, num_doors), battery_kw_(battery_kw)
    {
    }

    ~ElectricCar() override
    {
        std::cout << "Destroying electric car: " << name_
                  << " (" << battery_kw_ << " kW)" << std::endl;
    }

    // Override of Car::start() (and therefore Vehicle::start()).
    void start() override
    {
        std::cout << "Starting electric vehicle " << name_
                  << " with " << battery_kw_ << " kW battery" << std::endl;
        fuel_level_ -= 1;
    }

    // NON-virtual method specific to ElectricCar.
    void charge()
    {
        std::cout << name_ << ": charging battery (" << battery_kw_
                  << " kW)..." << std::endl;
        fuel_level_ = 100;
    }

private:
    int battery_kw_; // offset 0x38
    // 4 bytes padding → sizeof(ElectricCar) = 0x40 (64)
};

// ============================================================================
// main — Polymorphism demonstration
// ============================================================================

int main()
{
    // Array of base pointers — polymorphic dispatch via vtable.
    std::vector<Vehicle*> fleet;

    fleet.push_back(new Vehicle("Truck", 80));
    fleet.push_back(new Car("Sedan", 60, 4));
    fleet.push_back(new Motorcycle("Harley", 20, false));
    fleet.push_back(new ElectricCar("Tesla", 100, 4, 75));

    std::cout << "=== Fleet startup ===" << std::endl;

    // Virtual calls: start() and display_info() are resolved via the vptr
    // of each object. Each call goes through the vtable of the actual type.
    for (size_t i = 0; i < fleet.size(); ++i) {
        fleet[i]->start();          // virtual dispatch → slot [2]
        fleet[i]->display_info();   // virtual dispatch → slot [3] (always Vehicle::display_info)
        std::cout << "  fuel_level = " << fleet[i]->get_fuel_level() << std::endl;
        std::cout << std::endl;
    }

    std::cout << "=== Specific actions ===" << std::endl;

    // Non-virtual calls: require a cast to the derived type.
    // In the binary, these calls are direct CALLs (no vptr indirection).
    static_cast<Car*>(fleet[1])->open_trunk();
    static_cast<ElectricCar*>(fleet[3])->charge();

    std::cout << std::endl;
    std::cout << "=== Cleanup ===" << std::endl;

    // delete via base pointer: calls the virtual destructor (D0, deleting)
    // via slot [1] of the vtable. The correct destructor is called thanks to
    // polymorphism, even through a Vehicle*.
    for (size_t i = 0; i < fleet.size(); ++i) {
        delete fleet[i];
    }

    return 0;
}
