🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Solution — Chapter 8 Checkpoint

> **Spoilers** — This document contains the complete solution for the Chapter 8 checkpoint. Only consult it after attempting the exercise yourself.

---

## Context

The binary `ch08-oop_O0` is a C++ application compiled with `g++ -O0 -g`. It features a small vehicle management system using polymorphism, simple inheritance and two-level inheritance. The analysis is performed on the variant with symbols; a section at the end of the document addresses differences for the stripped variant.

---

## Step 1 — Import and Analysis

### Project Creation

1. **File → New Project → Non-Shared Project** in the Project Manager.  
2. Directory: `~/ghidra-projects/`, name: `ch08-checkpoint`.  
3. **File → Import File** → select `binaries/ch08-oop/ch08-oop_O0`.  
4. Verify the automatically detected import parameters:  
   - Format: `Executable and Linking Format (ELF)`  
   - Language: `x86:LE:64:default (gcc)`  
5. Validate the import.

### Auto Analysis

Click **Yes** to launch Auto Analysis. Verify that the following analyzers are enabled (they are by default):

- **Demangler GNU** — essential for C++, transforms `_ZN*` symbols into readable names.  
- **GCC Exception Handlers** — parses `.eh_frame` and `.gcc_except_table` tables.  
- **Decompiler Parameter ID** — infers parameter types via the decompiler.  
- **DWARF** — exploits debug information (present since compiled with `-g`).  
- **ASCII Strings** — identifies strings in `.rodata`.

Analysis takes a few seconds on this small binary. Wait until the progress bar disappears before starting exploration.

---

## Step 2 — Orientation and Class Identification

### Symbol Tree Exploration

Open the **Symbol Tree** (left panel of the CodeBrowser). Expand the **Functions** node. Thanks to the GNU Demangler and DWARF, functions are organized by namespace/class:

```
Functions
├── main
├── Vehicle
│   ├── Vehicle(std::string, int)
│   ├── ~Vehicle()
│   ├── display_info()
│   ├── start()
│   └── get_fuel_level()
├── Car
│   ├── Car(std::string, int, int)
│   ├── ~Car()
│   ├── start()
│   └── open_trunk()
├── Motorcycle
│   ├── Motorcycle(std::string, int, bool)
│   ├── ~Motorcycle()
│   └── start()
├── ElectricCar
│   ├── ElectricCar(std::string, int, int, int)
│   ├── ~ElectricCar()
│   ├── start()
│   └── charge()
└── (support functions: __libc_csu_init, _start, etc.)
```

**Observation** — Four classes identified directly from namespaces: `Vehicle`, `Car`, `Motorcycle`, `ElectricCar`.

### RTTI Verification

Search for typeinfo names via **Search → For Strings**, filter `Vehicle`:

| Address | String | Class |  
|---|---|---|  
| `0x00402200` | `7Vehicle` | `Vehicle` |  
| `0x00402210` | `3Car` | `Car` |  
| `0x00402218` | `10Motorcycle` | `Motorcycle` |  
| `0x00402228` | `11ElectricCar` | `ElectricCar` |

Navigate to associated `typeinfo for` structures:

**`typeinfo for Vehicle`** (`0x00402240`):

```
.rodata:00402240     addr    vtable for __class_type_info + 0x10
.rodata:00402248     addr    typeinfo name for Vehicle    ; → "7Vehicle"
```

→ `__class_type_info`: **Vehicle is a root class** (no polymorphic parent).

**`typeinfo for Car`** (`0x00402260`):

```
.rodata:00402260     addr    vtable for __si_class_type_info + 0x10
.rodata:00402268     addr    typeinfo name for Car        ; → "3Car"
.rodata:00402270     addr    typeinfo for Vehicle         ; parent
```

→ `__si_class_type_info` with `__base_type` → `Vehicle`: **Car inherits from Vehicle**.

**`typeinfo for Motorcycle`** (`0x00402280`):

```
.rodata:00402280     addr    vtable for __si_class_type_info + 0x10
.rodata:00402288     addr    typeinfo name for Motorcycle ; → "10Motorcycle"
.rodata:00402290     addr    typeinfo for Vehicle         ; parent
```

→ **Motorcycle inherits from Vehicle**.

**`typeinfo for ElectricCar`** (`0x004022a0`):

```
.rodata:004022a0     addr    vtable for __si_class_type_info + 0x10
.rodata:004022a8     addr    typeinfo name for ElectricCar ; → "11ElectricCar"
.rodata:004022b0     addr    typeinfo for Car              ; parent = Car, not Vehicle
```

→ **ElectricCar inherits from Car** (which itself inherits from Vehicle).

---

## Step 3 — Reconstructed Class Hierarchy

```
Vehicle                     ← root class (__class_type_info)
├── Car                     ← simple inheritance (__si_class_type_info, base = Vehicle)
│   └── ElectricCar         ← simple inheritance (__si_class_type_info, base = Car)
└── Motorcycle              ← simple inheritance (__si_class_type_info, base = Vehicle)
```

**Evidence**:

- The hierarchy is confirmed by three independent sources: RTTI (`__base_type` pointers), vptr initialization order in constructors, and parent constructor calls visible in the Decompiler.  
- All relationships are simple inheritance (all derived classes use `__si_class_type_info`, not `__vmi_class_type_info`).

---

## Step 4 — Vtable Analysis

### `vtable for Vehicle` (`0x00402300`)

```
.rodata:004022f0     addr    0x0                          ; offset-to-top
.rodata:004022f8     addr    typeinfo for Vehicle         ; RTTI
.rodata:00402300     addr    Vehicle::~Vehicle() [D1]     ; complete destructor
.rodata:00402308     addr    Vehicle::~Vehicle() [D0]     ; deleting destructor
.rodata:00402310     addr    Vehicle::start()             ; slot [2]
.rodata:00402318     addr    Vehicle::display_info()      ; slot [3]
```

→ 4 entries (2 destructors + 2 virtual methods: `start` and `display_info`).

### `vtable for Car` (`0x00402340`)

```
.rodata:00402330     addr    0x0                          ; offset-to-top
.rodata:00402338     addr    typeinfo for Car             ; RTTI
.rodata:00402340     addr    Car::~Car() [D1]             ; overridden destructor
.rodata:00402348     addr    Car::~Car() [D0]             ; overridden destructor
.rodata:00402350     addr    Car::start()                 ; override of Vehicle::start()
.rodata:00402358     addr    Vehicle::display_info()      ; INHERITED (same pointer as Vehicle)
```

→ `Car` overrides `start()` (different address from `Vehicle::start()`) but **inherits** `display_info()` without overriding (same address as in Vehicle's vtable).

### `vtable for Motorcycle` (`0x00402380`)

```
.rodata:00402370     addr    0x0
.rodata:00402378     addr    typeinfo for Motorcycle
.rodata:00402380     addr    Motorcycle::~Motorcycle() [D1]
.rodata:00402388     addr    Motorcycle::~Motorcycle() [D0]
.rodata:00402390     addr    Motorcycle::start()          ; override
.rodata:00402398     addr    Vehicle::display_info()      ; INHERITED
```

→ Same pattern as `Car`: overrides `start()`, inherits `display_info()`.

### `vtable for ElectricCar` (`0x004023c0`)

```
.rodata:004023b0     addr    0x0
.rodata:004023b8     addr    typeinfo for ElectricCar
.rodata:004023c0     addr    ElectricCar::~ElectricCar() [D1]
.rodata:004023c8     addr    ElectricCar::~ElectricCar() [D0]
.rodata:004023d0     addr    ElectricCar::start()         ; override
.rodata:004023d8     addr    Vehicle::display_info()      ; INHERITED (from Vehicle, via Car)
```

→ `ElectricCar` overrides `start()` a third time. `display_info()` remains Vehicle's throughout the hierarchy.

### Vtable Summary Table

| Slot | Vehicle | Car | Motorcycle | ElectricCar |  
|---|---|---|---|---|  
| [0] D1 dtor | `Vehicle::~Vehicle` | `Car::~Car` | `Motorcycle::~Motorcycle` | `ElectricCar::~ElectricCar` |  
| [1] D0 dtor | `Vehicle::~Vehicle` | `Car::~Car` | `Motorcycle::~Motorcycle` | `ElectricCar::~ElectricCar` |  
| [2] `start` | `Vehicle::start` | **`Car::start`** | **`Motorcycle::start`** | **`ElectricCar::start`** |  
| [3] `display_info` | `Vehicle::display_info` | `Vehicle::display_info` | `Vehicle::display_info` | `Vehicle::display_info` |

Cells in **bold** indicate an override (different pointer from parent). Normal cells indicate inheritance without override (same pointer).

**Observation** — No class contains `__cxa_pure_virtual` in its vtable. All classes are **concrete** (instantiable). `Vehicle` has a default implementation of `start()`, confirmed by reading its pseudo-code (it displays a generic message).

---

## Step 5 — Constructor Analysis and Field Reconstruction

### `Vehicle::Vehicle(std::string, int)`

Decompiler pseudo-code after DWARF analysis:

```c
void Vehicle::Vehicle(Vehicle * this, std::string name, int fuel_level)
{
    *(void **)this = &vtable_for_Vehicle + 0x10;  // vptr → Vehicle vtable
    *(std::string *)(this + 0x08) = name;          // string copy
    *(int *)(this + 0x28) = fuel_level;             // integer
    return;
}
```

`operator new` calls observed in `main`: `operator new(0x30)` for a `Vehicle`.

→ `sizeof(Vehicle)` = **0x30 (48 bytes)**.

Inferred layout:

| Offset | Size | Type | Field | Source |  
|---|---|---|---|---|  
| `0x00` | 8 | `void *` | `vptr` | Vtable address written in constructor |  
| `0x08` | 32 | `std::string` | `name` | Initialized by copy of `name` parameter; 32-byte size matches `sizeof(std::string)` of libstdc++ on x86-64 |  
| `0x28` | 4 | `int` | `fuel_level` | Initialized by `fuel_level` parameter |  
| `0x2c` | 4 | — | *(padding)* | Alignment to 0x30 for total structure size |

### `Car::Car(std::string, int, int)`

```c
void Car::Car(Car * this, std::string name, int fuel_level, int num_doors)
{
    Vehicle::Vehicle((Vehicle *)this, name, fuel_level);  // parent constructor call
    *(void **)this = &vtable_for_Car + 0x10;               // overwrites vptr → Car vtable
    *(int *)(this + 0x30) = num_doors;                      // own field
    return;
}
```

Call `operator new(0x38)` in `main`.

→ `sizeof(Car)` = **0x38 (56 bytes)**.

Inferred layout:

| Offset | Size | Type | Field | Source |  
|---|---|---|---|---|  
| `0x00` | 8 | `void *` | `vptr` | Inherited (overwritten to Car vtable) |  
| `0x08` | 32 | `std::string` | `name` | Inherited from Vehicle |  
| `0x28` | 4 | `int` | `fuel_level` | Inherited from Vehicle |  
| `0x2c` | 4 | — | *(inherited padding)* | — |  
| `0x30` | 4 | `int` | `num_doors` | Own to Car |  
| `0x34` | 4 | — | *(padding)* | Alignment to 0x38 |

**Key clue** — Car's constructor first calls `Vehicle::Vehicle(this, ...)`, then overwrites the vptr. This is the standard Itanium ABI pattern: the parent constructor initializes the vptr to its own vtable, then the derived constructor replaces it with its vtable. In reverse, this double vptr write confirms the inheritance relationship.

### `Motorcycle::Motorcycle(std::string, int, bool)`

```c
void Motorcycle::Motorcycle(Motorcycle * this, std::string name, int fuel_level,
                             bool has_sidecar)
{
    Vehicle::Vehicle((Vehicle *)this, name, fuel_level);
    *(void **)this = &vtable_for_Motorcycle + 0x10;
    *(bool *)(this + 0x30) = has_sidecar;
    return;
}
```

Call `operator new(0x38)` in `main`.

→ `sizeof(Motorcycle)` = **0x38 (56 bytes)** (same size as `Car`, but a single `bool` own field with 7 bytes of padding).

| Offset | Size | Type | Field | Source |  
|---|---|---|---|---|  
| `0x00` – `0x2f` | 48 | — | *(inherited Vehicle fields)* | Identical to Vehicle layout |  
| `0x30` | 1 | `bool` | `has_sidecar` | Own to Motorcycle |  
| `0x31` – `0x37` | 7 | — | *(padding)* | Alignment to 0x38 |

### `ElectricCar::ElectricCar(std::string, int, int, int)`

```c
void ElectricCar::ElectricCar(ElectricCar * this, std::string name,
                               int fuel_level, int num_doors, int battery_kw)
{
    Car::Car((Car *)this, name, fuel_level, num_doors);  // calls Car, not Vehicle
    *(void **)this = &vtable_for_ElectricCar + 0x10;
    *(int *)(this + 0x38) = battery_kw;
    return;
}
```

Call `operator new(0x40)` in `main`.

→ `sizeof(ElectricCar)` = **0x40 (64 bytes)**.

| Offset | Size | Type | Field | Source |  
|---|---|---|---|---|  
| `0x00` – `0x2f` | 48 | — | *(inherited Vehicle fields)* | — |  
| `0x30` | 4 | `int` | `num_doors` | Inherited from Car |  
| `0x34` | 4 | — | *(inherited padding)* | — |  
| `0x38` | 4 | `int` | `battery_kw` | Own to ElectricCar |  
| `0x3c` | 4 | — | *(padding)* | Alignment to 0x40 |

**Key clue** — The constructor calls `Car::Car` (not `Vehicle::Vehicle`), confirming that `ElectricCar` inherits from `Car`.

---

## Step 6 — Structures Created in the Data Type Manager

Four structures created in the program's category:

### `Vehicle` (0x30 = 48 bytes)

```
struct Vehicle {
    void *          vptr;           // 0x00
    std::string     name;           // 0x08  (32 bytes with libstdc++)
    int             fuel_level;     // 0x28
    byte[4]         _padding;       // 0x2c
};
```

### `Car` (0x38 = 56 bytes)

```
struct Car {
    Vehicle         _base;          // 0x00  (inheritance, 48 bytes)
    int             num_doors;      // 0x30
    byte[4]         _padding;       // 0x34
};
```

### `Motorcycle` (0x38 = 56 bytes)

```
struct Motorcycle {
    Vehicle         _base;          // 0x00  (inheritance, 48 bytes)
    bool            has_sidecar;    // 0x30
    byte[7]         _padding;       // 0x31
};
```

### `ElectricCar` (0x40 = 64 bytes)

```
struct ElectricCar {
    Car             _base;          // 0x00  (inheritance, 56 bytes)
    int             battery_kw;     // 0x38
    byte[4]         _padding;       // 0x3c
};
```

> **Implementation note** — Two approaches are possible for modeling inheritance in the Data Type Manager: including the parent structure as a first inline field (as above), or duplicating individual fields. The first approach is cleaner and better reflects semantics, but the Decompiler may display accesses as `this->_base._base.fuel_level` instead of `this->fuel_level`. The second is less elegant but produces more readable pseudo-code. Choose according to your preference.

After applying these structures to each method's `this` parameters (press `T` in the Decompiler), the pseudo-code becomes immediately readable. For example, `ElectricCar::start()`:

```c
// Before annotation
void FUN_00401800(long param_1)
{
    printf("Starting electric vehicle %s with %d kW battery\n",
           *(char **)(param_1 + 8), *(int *)(param_1 + 0x38));
    *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) - 1;
}

// After applying the ElectricCar structure
void ElectricCar::start(ElectricCar * this)
{
    printf("Starting electric vehicle %s with %d kW battery\n",
           this->_base._base.name.c_str, this->battery_kw);
    this->_base._base.fuel_level = this->_base._base.fuel_level - 1;
}
```

---

## Step 7 — Non-virtual Methods Identified

In addition to virtual methods listed in vtables, some classes have **non-virtual** methods that don't appear in vtables but are visible in the Symbol Tree:

| Class | Non-virtual method | Identification clue |  
|---|---|---|  
| `Vehicle` | `get_fuel_level()` | Present in the `Vehicle` namespace of the Symbol Tree. No vtable entry. Called directly by `CALL` (not via vptr indirection). |  
| `Car` | `open_trunk()` | Same observation. Direct call, no vtable slot. |  
| `ElectricCar` | `charge()` | Direct call only. |

**How to distinguish a virtual method from a non-virtual one in the disassembly** — Virtual calls go through an indirection: the code loads the vptr from the object (`MOV RAX, [RDI]`), indexes into the vtable (`MOV RAX, [RAX + offset]`), then calls via the register (`CALL RAX`). Non-virtual calls use a direct `CALL` to a constant address. In the Decompiler, the virtual call appears as `(*this->vptr[N])(this, ...)` and the direct call as `ClassName::method(this, ...)`.

---

## Step 8 — `main()` Analysis

The fully annotated `main()` pseudo-code summarizes the program's operation:

```c
int main(int argc, char ** argv)
{
    Vehicle * fleet[4];
    
    fleet[0] = new Vehicle("Truck", 80);
    fleet[1] = new Car("Sedan", 60, 4);
    fleet[2] = new Motorcycle("Harley", 20, false);
    fleet[3] = new ElectricCar("Tesla", 100, 4, 75);
    
    for (int i = 0; i < 4; i++) {
        fleet[i]->start();          // virtual call → polymorphic dispatch
        fleet[i]->display_info();   // virtual call → Vehicle::display_info for all
    }
    
    ((Car *)fleet[1])->open_trunk();       // non-virtual call, explicit cast
    ((ElectricCar *)fleet[3])->charge();   // non-virtual call, explicit cast
    
    for (int i = 0; i < 4; i++) {
        delete fleet[i];            // virtual call to deleting destructor [D0]
    }
    
    return 0;
}
```

**Key observations in `main()`**:

- The `fleet` array is a `Vehicle *` array — polymorphism is demonstrated by the fact that calls to `start()` all go through the vptr but execute different implementations depending on the object's actual type.  
- The calls to `open_trunk()` and `charge()` don't go through the vtable (non-virtual methods), and the code performs a cast to the derived type before the call.  
- The `delete` calls invoke the virtual destructor via slot [1] (deleting destructor D0), which guarantees the correct destructor is called even through a base pointer.

---

## Deliverable Summary

### Hierarchy Diagram

```
Vehicle                     [concrete, 0x30 bytes, 2 virtual methods + 1 non-virtual]
├── Car                     [concrete, 0x38 bytes, overrides start(), +1 non-virtual]
│   └── ElectricCar         [concrete, 0x40 bytes, overrides start(), +1 non-virtual]
└── Motorcycle              [concrete, 0x38 bytes, overrides start()]
```

### Metrics

- **4 classes** identified and documented.  
- **3 inheritance relationships** reconstructed, all confirmed by RTTI, constructors and vtables.  
- **4 vtables** analyzed, with 4 slots each (2 destructors + 2 virtual methods).  
- **4 structures** created in the Data Type Manager and applied to methods.  
- **1 virtual method overridden** (`start()`) by each derived class.  
- **1 virtual method inherited without override** (`display_info()`) throughout the hierarchy.  
- **3 non-virtual methods** identified (`get_fuel_level`, `open_trunk`, `charge`).

---

## Extension: `ch08-oop_O2_strip` Analysis

On the optimized and stripped variant, the main differences observed are:

**Function names lost** — All functions appear as `FUN_XXXXXXXX`. The Symbol Tree no longer has class namespaces. Methods must be identified by their content and position in vtables.

**RTTI still present** — The strings `7Vehicle`, `3Car`, `10Motorcycle`, `11ElectricCar` are still in `.rodata`. The `typeinfo for` structures are intact. The inheritance hierarchy is reconstructible exactly as on the non-stripped binary.

**Partial inlining** — With `-O2`, some short methods like `get_fuel_level()` are inlined into `main()`. They disappear as distinct functions. The number of detected functions is lower.

**Simplified constructors** — Constructors may be merged or partially inlined. The vptr initialization pattern remains identifiable, but parent constructor calls may be inlined directly.

**Additional analysis time** — Approximately 2 to 3 times longer than the version with symbols, mainly due to manual renaming work and method identification without the Demangler's help.

**Conclusion** — RTTI is the pivot of analysis on a stripped C++ binary. As long as it's present, the class hierarchy is recoverable. Method names require functional analysis (reading pseudo-code) to be reconstructed.

⏭️
