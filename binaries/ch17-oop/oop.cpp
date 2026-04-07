/**
 * Reverse Engineering Training — Chapter 17
 * Object-oriented C++ training binary
 *
 * This program intentionally exercises a maximum of C++ mechanisms that
 * the reverse engineer must know how to recognize in a GCC binary:
 *
 *   - Class hierarchy (simple + multiple inheritance)
 *   - Virtual and pure virtual methods (abstract classes)
 *   - RTTI enabled (dynamic_cast, typeid)
 *   - Custom exceptions (try/catch, __cxa_throw)
 *   - STL containers (vector, string, map, unordered_map)
 *   - Templates instantiated with multiple types
 *   - Lambdas with different capture modes
 *   - Smart pointers (unique_ptr, shared_ptr)
 *
 * Compilation: see Makefile (make all)
 * License: MIT — Strictly educational use
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <algorithm>
#include <functional>
#include <stdexcept>
#include <cmath>
#include <cstring>
#include <typeinfo>

// ============================================================================
// 1. CUSTOM EXCEPTIONS
//    In RE: look for __cxa_allocate_exception, __cxa_throw, __cxa_begin_catch
//           and typeinfo entries in .rodata
// ============================================================================

class AppException : public std::exception {
protected:
    std::string msg_;
    int code_;
public:
    AppException(const std::string& msg, int code)
        : msg_(msg), code_(code) {}

    const char* what() const noexcept override {
        return msg_.c_str();
    }

    int code() const noexcept { return code_; }
};

class ParseError : public AppException {
    int line_;
public:
    ParseError(const std::string& msg, int line)
        : AppException(msg, 100), line_(line) {}

    int line() const noexcept { return line_; }
};

class NetworkError : public AppException {
    std::string host_;
public:
    NetworkError(const std::string& msg, const std::string& host)
        : AppException(msg, 200), host_(host) {}

    const std::string& host() const noexcept { return host_; }
};

// ============================================================================
// 2. CLASS HIERARCHY — SIMPLE INHERITANCE
//    In RE: vtable per class in .rodata, vptr at offset 0 of each object,
//           constructors that initialize the vptr
// ============================================================================

class Shape {
protected:
    std::string name_;
    double x_, y_;  // position

public:
    Shape(const std::string& name, double x, double y)
        : name_(name), x_(x), y_(y) {}

    virtual ~Shape() = default;

    // Pure virtual method → Shape is abstract
    virtual double area() const = 0;
    virtual double perimeter() const = 0;

    // Virtual method with default implementation
    virtual std::string describe() const {
        return name_ + " at (" +
               std::to_string(x_) + ", " +
               std::to_string(y_) + ")";
    }

    // Non-virtual method
    const std::string& name() const { return name_; }

    void move(double dx, double dy) {
        x_ += dx;
        y_ += dy;
    }
};

class Circle : public Shape {
    double radius_;
public:
    Circle(double x, double y, double r)
        : Shape("Circle", x, y), radius_(r) {
        if (r <= 0) throw AppException("Invalid radius", 10);
    }

    double area() const override {
        return M_PI * radius_ * radius_;
    }

    double perimeter() const override {
        return 2.0 * M_PI * radius_;
    }

    std::string describe() const override {
        return Shape::describe() + " r=" + std::to_string(radius_);
    }

    double radius() const { return radius_; }
};

class Rectangle : public Shape {
    double width_, height_;
public:
    Rectangle(double x, double y, double w, double h)
        : Shape("Rectangle", x, y), width_(w), height_(h) {
        if (w <= 0 || h <= 0) throw AppException("Invalid dimensions", 11);
    }

    double area() const override {
        return width_ * height_;
    }

    double perimeter() const override {
        return 2.0 * (width_ + height_);
    }

    std::string describe() const override {
        return Shape::describe() +
               " w=" + std::to_string(width_) +
               " h=" + std::to_string(height_);
    }
};

class Triangle : public Shape {
    double a_, b_, c_;  // side lengths
public:
    Triangle(double x, double y, double a, double b, double c)
        : Shape("Triangle", x, y), a_(a), b_(b), c_(c) {
        if (a <= 0 || b <= 0 || c <= 0)
            throw AppException("Invalid side length", 12);
        if (a + b <= c || a + c <= b || b + c <= a)
            throw AppException("Triangle inequality violated", 13);
    }

    double area() const override {
        double s = (a_ + b_ + c_) / 2.0;
        return std::sqrt(s * (s - a_) * (s - b_) * (s - c_));
    }

    double perimeter() const override {
        return a_ + b_ + c_;
    }
};

// ============================================================================
// 3. MULTIPLE INHERITANCE
//    In RE: multiple vptrs in a single object, adjustment thunks,
//           multiple vtables in .rodata for the same class
// ============================================================================

class Drawable {
public:
    virtual ~Drawable() = default;
    virtual void draw() const = 0;
    virtual int zOrder() const { return 0; }
};

class Serializable {
public:
    virtual ~Serializable() = default;
    virtual std::string serialize() const = 0;
    virtual bool deserialize(const std::string& data) = 0;
};

// Multiple inheritance: Canvas inherits from Drawable AND Serializable
class Canvas : public Drawable, public Serializable {
    std::string title_;
    std::vector<std::shared_ptr<Shape>> shapes_;
    int z_order_;

public:
    Canvas(const std::string& title, int z = 0)
        : title_(title), z_order_(z) {}

    void addShape(std::shared_ptr<Shape> shape) {
        shapes_.push_back(shape);
    }

    // Implements Drawable::draw
    void draw() const override {
        std::cout << "=== Canvas: " << title_
                  << " (" << shapes_.size() << " shapes) ===" << std::endl;
        for (const auto& s : shapes_) {
            std::cout << "  " << s->describe()
                      << " | area=" << s->area() << std::endl;
        }
    }

    int zOrder() const override { return z_order_; }

    // Implements Serializable::serialize
    std::string serialize() const override {
        std::string out = "CANVAS:" + title_ + ":";
        out += std::to_string(shapes_.size());
        for (const auto& s : shapes_) {
            out += "|" + s->name() + ":" + std::to_string(s->area());
        }
        return out;
    }

    bool deserialize(const std::string& data) override {
        // Simplified implementation for the RE exercise
        if (data.substr(0, 7) != "CANVAS:")
            throw ParseError("Invalid canvas header", 1);
        title_ = data.substr(7, data.find(':', 7) - 7);
        return true;
    }

    double totalArea() const {
        double total = 0;
        for (const auto& s : shapes_) {
            total += s->area();
        }
        return total;
    }

    const std::string& title() const { return title_; }
    size_t shapeCount() const { return shapes_.size(); }
};

// ============================================================================
// 4. TEMPLATES
//    In RE: multiple instantiations → duplicated symbols with different types,
//           recognize identical patterns with varying access sizes
// ============================================================================

template<typename K, typename V>
class Registry {
    std::map<K, V> entries_;
    std::string name_;

public:
    explicit Registry(const std::string& name) : name_(name) {}

    void add(const K& key, const V& value) {
        if (entries_.count(key))
            throw AppException("Duplicate key in registry: " + name_, 300);
        entries_[key] = value;
    }

    const V& get(const K& key) const {
        auto it = entries_.find(key);
        if (it == entries_.end())
            throw AppException("Key not found in registry: " + name_, 301);
        return it->second;
    }

    bool contains(const K& key) const {
        return entries_.count(key) > 0;
    }

    size_t size() const { return entries_.size(); }

    // Iteration with callback (lambda exercise)
    void forEach(std::function<void(const K&, const V&)> callback) const {
        for (const auto& [k, v] : entries_) {
            callback(k, v);
        }
    }

    // Filtering with template predicate
    template<typename Pred>
    std::vector<K> filter(Pred predicate) const {
        std::vector<K> result;
        for (const auto& [k, v] : entries_) {
            if (predicate(k, v)) {
                result.push_back(k);
            }
        }
        return result;
    }
};

// ============================================================================
// 5. FUNCTIONS USING LAMBDAS
//    In RE: anonymous classes generated by the compiler, operator() in the
//           vtable, captures visible in the closure's memory layout
// ============================================================================

static void demonstrateLambdas(const std::vector<std::shared_ptr<Shape>>& shapes) {
    std::cout << "\n--- Lambda demonstrations ---" << std::endl;

    // Lambda without capture
    auto printSeparator = []() {
        std::cout << "------------------------" << std::endl;
    };

    // Lambda with capture by value
    double minArea = 10.0;
    auto isLargeShape = [minArea](const std::shared_ptr<Shape>& s) {
        return s->area() > minArea;
    };

    // Lambda with capture by reference
    double totalArea = 0.0;
    int count = 0;
    auto accumulate = [&totalArea, &count](const std::shared_ptr<Shape>& s) {
        totalArea += s->area();
        count++;
    };

    // Lambda with mixed capture (value + reference)
    std::string prefix = ">> ";
    std::vector<std::string> descriptions;
    auto describeAndCollect = [prefix, &descriptions](const std::shared_ptr<Shape>& s) {
        std::string desc = prefix + s->describe();
        descriptions.push_back(desc);
        std::cout << desc << std::endl;
    };

    // Generic lambda (C++14) — capture everything by copy
    auto formatShape = [=](const auto& s) -> std::string {
        return prefix + s->name() + " (area >= " +
               std::to_string(minArea) + "? " +
               (s->area() >= minArea ? "yes" : "no") + ")";
    };

    printSeparator();

    // Usage with std::for_each
    std::for_each(shapes.begin(), shapes.end(), accumulate);
    std::cout << "Total shapes: " << count
              << ", Total area: " << totalArea << std::endl;

    printSeparator();

    // Usage with std::count_if
    auto largeCount = std::count_if(shapes.begin(), shapes.end(), isLargeShape);
    std::cout << "Large shapes (area > " << minArea << "): "
              << largeCount << std::endl;

    printSeparator();

    // Describe each shape
    std::for_each(shapes.begin(), shapes.end(), describeAndCollect);

    printSeparator();

    // Use the generic lambda
    for (const auto& s : shapes) {
        std::cout << formatShape(s) << std::endl;
    }
}

// ============================================================================
// 6. FUNCTIONS USING SMART POINTERS
//    In RE: unique_ptr → nearly transparent (inlined), shared_ptr → atomic
//           counter, control block, calls to __shared_count
// ============================================================================

struct Config {
    std::string name;
    int maxShapes;
    bool verbose;

    Config(const std::string& n, int m, bool v)
        : name(n), maxShapes(m), verbose(v) {}
};

static void demonstrateSmartPointers() {
    std::cout << "\n--- Smart pointer demonstrations ---" << std::endl;

    // unique_ptr — ownership transfer
    auto config = std::make_unique<Config>("default", 100, true);
    std::cout << "Config: " << config->name
              << ", max=" << config->maxShapes << std::endl;

    // Ownership transfer
    auto config2 = std::move(config);
    // config is now nullptr
    if (!config) {
        std::cout << "Original config moved, now null" << std::endl;
    }
    std::cout << "Moved config: " << config2->name << std::endl;

    // shared_ptr — shared ownership with reference counting
    auto sharedCircle = std::make_shared<Circle>(0, 0, 5.0);
    std::cout << "Circle refcount: " << sharedCircle.use_count() << std::endl;

    {
        // Copy → increments the counter
        auto copy1 = sharedCircle;
        auto copy2 = sharedCircle;
        std::cout << "After 2 copies, refcount: "
                  << sharedCircle.use_count() << std::endl;

        // weak_ptr — weak reference, does not keep the object alive
        std::weak_ptr<Circle> weakRef = sharedCircle;
        std::cout << "Weak ref expired? "
                  << (weakRef.expired() ? "yes" : "no") << std::endl;

        if (auto locked = weakRef.lock()) {
            std::cout << "Locked weak_ptr, radius: "
                      << locked->radius() << std::endl;
            std::cout << "Refcount during lock: "
                      << sharedCircle.use_count() << std::endl;
        }
    }
    // copy1 and copy2 destroyed → counter decreases
    std::cout << "After scope exit, refcount: "
              << sharedCircle.use_count() << std::endl;

    // shared_ptr in a container
    std::vector<std::shared_ptr<Shape>> shapeVec;
    shapeVec.push_back(sharedCircle);
    shapeVec.push_back(std::make_shared<Rectangle>(1, 1, 4, 3));
    shapeVec.push_back(std::make_shared<Triangle>(0, 0, 3, 4, 5));

    std::cout << "Circle refcount in vector: "
              << sharedCircle.use_count() << std::endl;

    // unique_ptr with array (rare but exists in RE)
    auto buffer = std::make_unique<char[]>(256);
    std::strcpy(buffer.get(), "RE training buffer");
    std::cout << "Buffer content: " << buffer.get() << std::endl;
}

// ============================================================================
// 7. USING std::unordered_map AND RTTI
//    In RE: hash table internals, typeid / dynamic_cast
// ============================================================================

static void demonstrateRTTI(const std::vector<std::shared_ptr<Shape>>& shapes) {
    std::cout << "\n--- RTTI demonstrations ---" << std::endl;

    // Type counting with typeid
    std::unordered_map<std::string, int> typeCounts;

    for (const auto& s : shapes) {
        // typeid produces references to typeinfo in .rodata
        std::string typeName = typeid(*s).name();
        typeCounts[typeName]++;

        std::cout << "Shape: " << s->name()
                  << " | typeid: " << typeName << std::endl;
    }

    std::cout << "\nType distribution:" << std::endl;
    for (const auto& [type, count] : typeCounts) {
        std::cout << "  " << type << ": " << count << std::endl;
    }

    // dynamic_cast — runtime type checking
    for (const auto& s : shapes) {
        if (auto* circle = dynamic_cast<Circle*>(s.get())) {
            std::cout << "Found Circle with radius: "
                      << circle->radius() << std::endl;
        } else if (dynamic_cast<Rectangle*>(s.get())) {
            std::cout << "Found Rectangle, area: "
                      << s->area() << std::endl;
        } else if (dynamic_cast<Triangle*>(s.get())) {
            std::cout << "Found Triangle, perimeter: "
                      << s->perimeter() << std::endl;
        }
    }
}

// ============================================================================
// 8. ENTRY POINT — EXERCISES THE ENTIRE PROGRAM
// ============================================================================

int main(int argc, char* argv[]) {
    bool verbose = false;
    if (argc > 1 && std::string(argv[1]) == "-v") {
        verbose = true;
    }

    try {
        // --- Shape creation (smart pointers) ---
        auto c1 = std::make_shared<Circle>(0, 0, 5.0);
        auto c2 = std::make_shared<Circle>(10, 10, 3.0);
        auto r1 = std::make_shared<Rectangle>(5, 5, 4.0, 6.0);
        auto r2 = std::make_shared<Rectangle>(0, 10, 2.0, 8.0);
        auto t1 = std::make_shared<Triangle>(3, 3, 3.0, 4.0, 5.0);

        std::vector<std::shared_ptr<Shape>> allShapes = {c1, c2, r1, r2, t1};

        // --- Registry (template instantiated with two types) ---
        Registry<std::string, std::shared_ptr<Shape>> shapeRegistry("shapes");
        shapeRegistry.add("main_circle", c1);
        shapeRegistry.add("small_circle", c2);
        shapeRegistry.add("main_rect", r1);
        shapeRegistry.add("side_rect", r2);
        shapeRegistry.add("triangle", t1);

        Registry<int, std::string> idRegistry("ids");
        idRegistry.add(1, "circle_main");
        idRegistry.add(2, "circle_small");
        idRegistry.add(3, "rect_main");
        idRegistry.add(4, "rect_side");
        idRegistry.add(5, "triangle");

        // --- Access via the registry ---
        std::cout << "Registry lookup: "
                  << shapeRegistry.get("main_circle")->describe() << std::endl;
        std::cout << "ID lookup: "
                  << idRegistry.get(3) << std::endl;

        // --- Filtering with lambda in the template ---
        auto largeShapeKeys = shapeRegistry.filter(
            [](const std::string& key, const std::shared_ptr<Shape>& s) {
                return s->area() > 20.0;
            }
        );
        std::cout << "\nShapes with area > 20:" << std::endl;
        for (const auto& key : largeShapeKeys) {
            std::cout << "  " << key << ": "
                      << shapeRegistry.get(key)->describe() << std::endl;
        }

        // --- Canvas (multiple inheritance) ---
        Canvas canvas("Main Canvas", 1);
        for (const auto& s : allShapes) {
            canvas.addShape(s);
        }
        canvas.draw();

        std::cout << "\nCanvas total area: "
                  << canvas.totalArea() << std::endl;

        // --- Serialization (Serializable interface) ---
        std::string serialized = canvas.serialize();
        std::cout << "Serialized: " << serialized << std::endl;

        // --- Drawable interface ---
        Drawable* drawable = &canvas;
        drawable->draw();
        std::cout << "Z-order: " << drawable->zOrder() << std::endl;

        // --- Deserialization test ---
        Canvas canvas2("Empty", 0);
        canvas2.deserialize(serialized);
        std::cout << "Deserialized canvas title: "
                  << canvas2.title() << std::endl;

        // --- Lambdas ---
        demonstrateLambdas(allShapes);

        // --- Smart pointers ---
        demonstrateSmartPointers();

        // --- RTTI ---
        demonstrateRTTI(allShapes);

        // --- forEach with the Registry ---
        if (verbose) {
            std::cout << "\n--- Full registry dump ---" << std::endl;
            shapeRegistry.forEach(
                [](const std::string& key, const std::shared_ptr<Shape>& s) {
                    std::cout << "  [" << key << "] "
                              << s->describe()
                              << " | area=" << s->area()
                              << " | perimeter=" << s->perimeter()
                              << std::endl;
                }
            );

            idRegistry.forEach(
                [](const int& id, const std::string& name) {
                    std::cout << "  ID " << id << " -> " << name << std::endl;
                }
            );
        }

        // --- Polymorphism via base pointer ---
        std::cout << "\n--- Polymorphic iteration ---" << std::endl;
        for (const auto& s : allShapes) {
            // Virtual call: the vptr determines which method is called
            std::cout << s->describe()
                      << " | area=" << s->area()
                      << " | perimeter=" << s->perimeter()
                      << std::endl;
        }

    } catch (const ParseError& e) {
        std::cerr << "[ParseError] line " << e.line()
                  << ": " << e.what()
                  << " (code " << e.code() << ")" << std::endl;
        return 2;
    } catch (const NetworkError& e) {
        std::cerr << "[NetworkError] host " << e.host()
                  << ": " << e.what()
                  << " (code " << e.code() << ")" << std::endl;
        return 3;
    } catch (const AppException& e) {
        std::cerr << "[AppException] " << e.what()
                  << " (code " << e.code() << ")" << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "[std::exception] " << e.what() << std::endl;
        return 99;
    }

    std::cout << "\n✓ All demonstrations completed." << std::endl;
    return 0;
}
