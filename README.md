# P2P Handshake exercise
Solution is using the Ethereum P2P node protocol for communication. 
The implementation is based on the RLPx protocol described in [RLPx](https://github.com/ethereum/devp2p/blob/master/rlpx.md)
and discovery protocol described in [DiscV4](https://github.com/ethereum/devp2p/blob/master/discv4.md).

First the application sends PING message using UDP packet to check whether target node exists.
This step is not required when connecting to the p2p node, but is usable for checking the reachability of nodes.

Next step is to do a P2P handshake using messages described in RPLx protocol.
First the **Auth message** is send. 
The target node responses with the **Ack message** where we get enough information to derive secrets out of it.
Last step is to send the **Hello message**. 
This way the connection is established.
There should be additional steps to ensure that the connection is secured, 
like checking the MAC value in the incoming Hello message, 
or sending the Capability message to agree on the next communication protocol,
etc.
But none of these steps is required to create a connection.
More information about the message formats is included in the source files.


## Dependencies
* The project requires to have nodejs installed. Some part of the solution uses a JS dependencies.
    The reason for it is that I could not find any maintained implementations of ecdhX and concatKDF methods.
    For this I have decided to use a library implemented in different language and these were the most maintained.
    Using a rust crate instead (if some exists) is not a complicated task to do.
* No other dependencies are required


## How to test
* Download some ethereum node, for example [go-ethereum](https://geth.ethereum.org/downloads/)
* Run this node with verbosity at least 4 to see when this node connects to the geth node
  * `./geth --verbosity 4`
* In different terminal run this node, as an argument it requires the remote node ID
  * `cargo r -- -r <hex-node-id>`
* Then this node should output that the connection is successfully created
* In previous terminal that is running *geth* node you should see that this node has connected with name "Michal Režňák"
* If needed address and port can be changed
  * `cargo r -- -r <hex-node-id> -a <address> -p <port>`
