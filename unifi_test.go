package main

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/filipowm/go-unifi/unifi"
)

const simulationGroupSize = 10000

func TestGetKeysReturnsSortedAddresses(t *testing.T) {
	addresses := map[string]bool{
		"203.0.113.10": true,
		"198.51.100.2": true,
		"192.0.2.1":    true,
	}

	got := getKeys(addresses)
	want := []string{"192.0.2.1", "198.51.100.2", "203.0.113.10"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("getKeys() = %v, want %v", got, want)
	}
}

func TestSameStringSetIgnoresOrder(t *testing.T) {
	if !sameStringSet([]string{"b", "a"}, []string{"a", "b"}) {
		t.Fatal("sameStringSet() returned false for the same members in different order")
	}
}

func TestPostFirewallGroupSkipsUnchangedMembers(t *testing.T) {
	client := &firewallGroupClient{}
	mal := &unifiAddrList{
		c: client,
		firewallGroups: map[bool]map[string]string{
			false: {"cs-unifi-bouncer-ipv4-0": "group-id"},
			true:  {},
		},
		firewallGroupMembers: map[bool]map[string][]string{
			false: {"cs-unifi-bouncer-ipv4-0": {"198.51.100.2", "192.0.2.1"}},
			true:  {},
		},
	}

	groupID := mal.postFirewallGroup(context.Background(), "group-id", "cs-unifi-bouncer-ipv4-0", false, []string{"192.0.2.1", "198.51.100.2"})

	if groupID != "group-id" {
		t.Fatalf("postFirewallGroup() returned %q, want %q", groupID, "group-id")
	}
	if client.updateCalls != 0 {
		t.Fatalf("UpdateFirewallGroup() calls = %d, want 0", client.updateCalls)
	}
}

func TestPostFirewallGroupUpdatesChangedMembers(t *testing.T) {
	client := &firewallGroupClient{}
	mal := &unifiAddrList{
		c: client,
		firewallGroups: map[bool]map[string]string{
			false: {"cs-unifi-bouncer-ipv4-0": "group-id"},
			true:  {},
		},
		firewallGroupMembers: map[bool]map[string][]string{
			false: {"cs-unifi-bouncer-ipv4-0": {"192.0.2.1"}},
			true:  {},
		},
	}

	groupID := mal.postFirewallGroup(context.Background(), "group-id", "cs-unifi-bouncer-ipv4-0", false, []string{"192.0.2.1", "198.51.100.2"})

	if groupID != "group-id" {
		t.Fatalf("postFirewallGroup() returned %q, want %q", groupID, "group-id")
	}
	if client.updateCalls != 1 {
		t.Fatalf("UpdateFirewallGroup() calls = %d, want 1", client.updateCalls)
	}
	if !sameStringSet(mal.firewallGroupMembers[false]["cs-unifi-bouncer-ipv4-0"], []string{"192.0.2.1", "198.51.100.2"}) {
		t.Fatalf("cached members = %v, want updated members", mal.firewallGroupMembers[false]["cs-unifi-bouncer-ipv4-0"])
	}
}

func TestUnsortedMapChunkingChurn(t *testing.T) {
	addresses := generateSortableAddresses(6)
	firstOrder := []string{addresses[0], addresses[1], addresses[2], addresses[3], addresses[4], addresses[5]}
	secondOrder := []string{addresses[3], addresses[4], addresses[5], addresses[0], addresses[1], addresses[2]}

	before := chunkAddresses(firstOrder, 3)
	after := chunkAddresses(secondOrder, 3)
	changed := changedGroupCount(before, after)

	if changed != 2 {
		t.Fatalf("changed groups = %d, want 2", changed)
	}
}

func TestSortedChunkingReducesOrderOnlyChurn(t *testing.T) {
	addresses := generateSortableAddresses(6)
	firstOrder := []string{addresses[0], addresses[1], addresses[2], addresses[3], addresses[4], addresses[5]}
	secondOrder := []string{addresses[3], addresses[4], addresses[5], addresses[0], addresses[1], addresses[2]}

	before := chunkSortedAddresses(firstOrder, 3)
	after := chunkSortedAddresses(secondOrder, 3)
	changed := changedGroupCount(before, after)

	if changed != 0 {
		t.Fatalf("changed groups = %d, want 0", changed)
	}
}

func TestSortedChunkingChurnScenarios(t *testing.T) {
	base := generateSortableAddresses(100000)
	baseGroups := chunkSortedAddresses(base, simulationGroupSize)

	tests := []struct {
		name string
		list []string
		want int
	}{
		{
			name: "add at end",
			list: appendAddress(base, "ip-999999"),
			want: 1,
		},
		{
			name: "add near beginning",
			list: appendAddress(base, "ip--00001"),
			want: 11,
		},
		{
			name: "remove near beginning",
			list: removeAddressAt(base, 0),
			want: 10,
		},
		{
			name: "add and remove random addresses",
			list: mutateRandomAddresses(base),
			want: 9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := changedGroupCount(baseGroups, chunkSortedAddresses(tt.list, simulationGroupSize))
			t.Logf("%s changed %d/%d groups", tt.name, changed, len(baseGroups))

			if changed != tt.want {
				t.Fatalf("changed groups = %d, want %d", changed, tt.want)
			}
		})
	}
}

func BenchmarkChunking100k(b *testing.B) {
	addresses := generateSortableAddresses(100000)

	b.ResetTimer()
	for range b.N {
		_ = chunkSortedAddresses(addresses, simulationGroupSize)
	}
}

type firewallGroupClient struct {
	unifi.Client
	updateCalls int
	createCalls int
}

func (c *firewallGroupClient) UpdateFirewallGroup(_ context.Context, _ string, group *unifi.FirewallGroup) (*unifi.FirewallGroup, error) {
	c.updateCalls++
	return group, nil
}

func (c *firewallGroupClient) CreateFirewallGroup(_ context.Context, _ string, group *unifi.FirewallGroup) (*unifi.FirewallGroup, error) {
	c.createCalls++
	return group, nil
}

func generateSortableAddresses(count int) []string {
	addresses := make([]string, count)
	for i := range count {
		addresses[i] = fmt.Sprintf("ip-%06d", i)
	}
	return addresses
}

func chunkAddresses(addresses []string, groupSize int) [][]string {
	groups := make([][]string, 0, (len(addresses)+groupSize-1)/groupSize)
	for i := 0; i < len(addresses); i += groupSize {
		end := i + groupSize
		if end > len(addresses) {
			end = len(addresses)
		}
		groups = append(groups, addresses[i:end])
	}
	return groups
}

func chunkSortedAddresses(addresses []string, groupSize int) [][]string {
	addressMap := make(map[string]bool, len(addresses))
	for _, address := range addresses {
		addressMap[address] = true
	}
	return chunkAddresses(getKeys(addressMap), groupSize)
}

func changedGroupCount(before [][]string, after [][]string) int {
	changed := 0
	maxGroups := max(len(before), len(after))
	for i := range maxGroups {
		var beforeGroup []string
		if i < len(before) {
			beforeGroup = before[i]
		}

		var afterGroup []string
		if i < len(after) {
			afterGroup = after[i]
		}

		if !sameStringSet(beforeGroup, afterGroup) {
			changed++
		}
	}
	return changed
}

func appendAddress(addresses []string, address string) []string {
	mutated := slices.Clone(addresses)
	return append(mutated, address)
}

func removeAddressAt(addresses []string, index int) []string {
	mutated := make([]string, 0, len(addresses)-1)
	mutated = append(mutated, addresses[:index]...)
	mutated = append(mutated, addresses[index+1:]...)
	return mutated
}

func mutateRandomAddresses(addresses []string) []string {
	mutated := slices.Clone(addresses)
	removeIndexes := []int{123, 4567, 23456, 45678, 67890}
	for i := len(removeIndexes) - 1; i >= 0; i-- {
		mutated = removeAddressAt(mutated, removeIndexes[i])
	}
	for _, address := range []string{"ip-012345-a", "ip-034567-a", "ip-055555-a", "ip-078901-a", "ip-088888-a"} {
		mutated = append(mutated, address)
	}
	return mutated
}
