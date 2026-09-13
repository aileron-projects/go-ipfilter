package ipfilter

// trieNode is the node for trie trees.
// Here, trie tree is for ip whitelist and blacklist.
// See https://en.wikipedia.org/wiki/Trie.
type trieNode struct {
	children [2]*trieNode
	isSubnet bool
}

// rootNode is the root node for a trie tree.
type rootNode trieNode

// add adds ip address with or without subnet with the bits.
// It ignores ips with invalid bits.
// "<ipv4>/0" or "<ipv6>/0" matches all ip addresses.
func (n *rootNode) add(bits int, ip []byte) {
	if bits < 0 || bits > len(ip)*8 {
		return // Invalid bits.
	}

	node := (*trieNode)(n)
	if bits == 0 {
		node.isSubnet = true
		return
	}

	count := 0
Loop:
	for _, b := range ip {
		for i := range 8 { // Loop over 8 bits.
			bit := (b >> (7 - i)) & 1
			if node.children[bit] == nil {
				node.children[bit] = &trieNode{}
			}
			node = node.children[bit]
			if count++; count >= bits {
				break Loop
			}
		}
	}
	node.isSubnet = true
}

func (n *rootNode) contains(ip []byte) bool {
	node := (*trieNode)(n)
	for _, b := range ip {
		for i := range 8 { // Loop over 8 bits.
			if node == nil {
				return false
			}
			if node.isSubnet {
				return true
			}
			bit := (b >> (7 - i)) & 1
			node = node.children[bit]
		}
	}
	return node != nil && node.isSubnet
}
