package com.cbs.secureService.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {

//  @Query(value = """
//      select t from Token t\s
//      where u.id = :id and (t.expired = false or t.revoked = false)\s
//      """)
//  Optional<Token> findValidTokenByUser(Long id);

  @Query(value = """
      select t from Token t\s
      where t.user.id = :id\s
      """)
  Token findTokenByUser(Long id);

  Optional<Token> findByToken(String token);
}
