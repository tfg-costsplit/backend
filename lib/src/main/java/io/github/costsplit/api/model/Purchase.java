package io.github.costsplit.api.model;

import java.util.Map;

/// @param id purchase id
/// @param price how much was paid in the purchase
/// @param name name of the purchase
/// @param payments Mapping from emails to amounts to pay
public record Purchase(long id, long price, String name, Map<String, Long> payments) {
    /// @param price how much was paid in the purchase
    /// @param name name of the purchase
    /// @param payments Mapping from emails to amounts to pay
    public Purchase(long price, String name, Map<String, Long> payments) {
        this(0, price, name, payments);
    }
}
