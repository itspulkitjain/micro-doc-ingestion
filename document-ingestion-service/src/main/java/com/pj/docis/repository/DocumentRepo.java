package com.pj.docis.repository;

import com.pj.docis.entity.DocumentEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DocumentRepo extends JpaRepository<DocumentEntity, Long> {
}
