# Third-party components

The Burp extension JAR bundles the components below. Their license and notice texts
are included under [META-INF/uce-third-party](src/main/resources/META-INF/uce-third-party)
in the source tree and the JAR.

| Component | Version | License |
|---|---|---|
| Jackson Core, Databind and Annotations | 2.15.2 | Apache-2.0 |
| Apache HttpClient | 4.5.14 | Apache-2.0 |
| Apache HttpCore | 4.4.16 | Apache-2.0 |
| Apache Commons Codec | 1.15 | Apache-2.0 |
| Apache Commons Logging | 1.2 | Apache-2.0 |
| FlatLaf | 3.2.5 | Apache-2.0 |
| RSyntaxTextArea | 3.4.0 | BSD-3-Clause |
| Bouncy Castle Provider | 1.70 | MIT |
| Mozilla Rhino | 1.8.1 | MPL-2.0 |

The Bouncy Castle provider ships as the original signed JAR. The Rhino classes
come from the upstream binary release. The corresponding source is available
from the [Rhino 1.8.1 Maven source archive](https://repo.maven.apache.org/maven2/org/mozilla/rhino/1.8.1/rhino-1.8.1-sources.jar).

Burp supplies the Montoya API at runtime.
