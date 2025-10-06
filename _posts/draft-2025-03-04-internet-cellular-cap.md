# A Look at Internet and Cellular Routing From the Perspective of Brewer's Theorem

[Brewer's Theorem](https://en.wikipedia.org/wiki/CAP_theorem), or the CAP theorem as it is more commonly referred to, states that a distributed data store can only provide two of the three guarantees of Consistency, Availability and Partition Tolerance. In practice, this means that any system that dynamically serves and updates information must tolerate one of the following three behaviors:

- a) Potentially return an outdated/stale response for a given request (!Consistency),
- b) Potentially return a non-response for any given request (!Availability), or
- c) Require all nodes to be operable and responsive to each other in order for requests to be correctly serviced (!Partition Tolerance).

## How does this relate to communications networks?

Internet and Cellular networks can be viewed as distributed systems where the primary "data" being queried is routing information. Clients "query" for routes to a specified destination (IP Address for Internet, or MSISDN (phone number) for cellular). The query in this case is implicit--in both cases the path of the route is not explicitly returned to the client, but rather the client sends data through the network with a requested destination and the network provides a route for that data.

Neither IP addresses nor MSISDNs are static--in both cases, an individual may change the location within the network topology in which their identifier resides. For the Internet, these updates to IP address locations are handled using [Border Gateway Protocol (BGP)](https://en.wikipedia.org/wiki/Border_Gateway_Protocol).


Not so in Cellular. Mobile networks need to guarantee high availability--remember that most countries entire emergency services infrastructure relies on cellular networks. And unlike the Internet, where IP addresses often keep to the same Autonomous System for years or even decades, mobile phones constantly move to new serving areas--_it's in the name_. This means frequent write updates to the route that should be taken to reach said phone. 














