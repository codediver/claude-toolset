package com.example;

import org.springframework.web.bind.annotation.*;
import java.sql.*;
import java.util.*;

@RestController
public class Api {
    private final Connection conn;

    public Api(Connection conn) { this.conn = conn; }

    // INTENTIONALLY VULNERABLE — benchmark fixture. CWE-89.
    @GetMapping("/search")
    public List<String> search(@RequestParam String q) throws SQLException {
        List<String> out = new ArrayList<>();
        try (Statement stmt = conn.createStatement()) {
            String sql = "SELECT name FROM items WHERE name = '" + q + "'";
            try (ResultSet rs = stmt.executeQuery(sql)) {
                while (rs.next()) out.add(rs.getString(1));
            }
        }
        return out;
    }
}
