registry-interceptor
====================
### Use with
- [dirkarnez/cpp-registry-playground](https://github.com/dirkarnez/cpp-registry-playground)

### Notes
- It is not that simple that we can blindly hook functions, it will probably fail when the target application have fancy use of those functions (e.g. call the same function multiple times to get value)
- All reading functions
  - `RegEnumKeyA`
  - `RegEnumKeyExA`
  - `RegEnumKeyExW`
  - `RegEnumKeyW`
  - `RegEnumValueA`
  - `RegEnumValueW`
  - `RegGetValueA`
  - `RegGetValueW`
  - `RegOpenKeyA`
  - `RegOpenKeyExA`
  - `RegOpenKeyExW`
  - `RegOpenKeyW`
  - `RegQueryMultipleValuesA`
  - `RegQueryMultipleValuesW`
  - `RegQueryValueA`
  - `RegQueryValueExA`
  - `RegQueryValueExW`
  - `RegQueryValueW`

### Reference
- https://github.com/ConsciousHacker/WFH/blob/main/registry.js
- https://github.com/xforcered/WFH/blob/main/registry.js
- **https://github.com/azurda/CB_TRAINING_DBI/blob/master/05_child_instrumentation/script.js**
- Search [`https://github.com/search?q=Module.findExportByName%28%22advapi32.dll%22+Reg&type=code`](https://github.com/search?q=Module.findExportByName%28%22advapi32.dll%22+Reg&type=code)
