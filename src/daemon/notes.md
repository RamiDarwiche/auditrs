# Async Actors with Tokio
https://ryhl.io/blog/actors-with-tokio/

An actor is an entity that spawns a self-contained task that does some work independantly of the rest of the program. Communication between actors is often done through message passing, where actors send messages to each other to request work or share information. This allows for a high degree of concurrency and can help to simplify the design of complex systems.


When to use a handle?? A handle is a reference to an actor that allows you to send messages to it. You would use a handle when you want to interact with an actor from outside of its own task. For example, if you have a web server that needs to communicate with a database actor, you would use a handle to send messages to the database actor from the web server.