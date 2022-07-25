package com.codestates.security.repository;

import com.codestates.security.model.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {

    public Member findByUsername(String username);
}
