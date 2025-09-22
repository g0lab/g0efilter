# Third-Party License Notice

This project uses third-party dependencies that may have different license terms than the main project.

## golang.org/x/text

**Package:** golang.org/x/text  
**Version:** v0.29.0  
**Primary License:** BSD-3-Clause  
**Additional Components:** Some Unicode data under CC-BY-SA-3.0  
**Usage:** Internationalized Domain Names (IDNA) support and text processing  
**Dependency Type:** Both direct (via golang.org/x/net) and transitive (via github.com/miekg/dns)

### License Details

The `golang.org/x/text` package is primarily licensed under the BSD-3-Clause license, which is permissive and compatible with commercial use. However, certain Unicode data files are licensed under CC-BY-SA-3.0.

### CC-BY-SA-3.0 Components

The CC-BY-SA-3.0 licensed components consist primarily of:
- **Unicode Character Database (UCD) data** - Factual compilation of Unicode character properties
- **Common Locale Data Repository (CLDR) data** - Standardized locale data from Unicode Consortium
- **Collation tables** - Language-specific sorting rules based on Unicode standards

### Justification

1. **Nature of Content**: The CC-BY-SA-3.0 licensed components are factual data compilations and standardized reference tables, not creative or copyrightable code.

2. **Industry Standard**: This is a widely-used Go standard library extension that many projects depend on, including major open-source projects.

3. **Essential Functionality**: Required for proper internationalized domain name (IDNA) handling and Unicode text processing in a network filtering application.

4. **Limited Scope**: The copyleft nature of CC-BY-SA-3.0 applies only to the Unicode data tables themselves, not to the application code that uses them.

5. **Transitive Dependency**: Even if not used directly, this dependency is pulled in by essential DNS libraries (`github.com/miekg/dns`).

### References

- [golang.org/x/text repository](https://github.com/golang/text)
- [Unicode License Terms](https://unicode.org/license.txt)
- [CLDR License](https://github.com/unicode-org/cldr/blob/main/LICENSE)

---

**Note**: This notice is provided for license compliance and transparency. The use of these components is considered acceptable for the intended use case of this software.