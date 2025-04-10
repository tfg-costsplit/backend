package io.github.costsplit.app.orm;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Credential {
    @Id
    private String email;
    private String name;
    private String hash;
    private String salt;
}
