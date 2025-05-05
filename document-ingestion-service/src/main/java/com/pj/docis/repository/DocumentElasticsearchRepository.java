package com.pj.docis.repository;

import com.pj.docis.entity.DocumentElasticsearch;
import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;

import java.util.List;

public interface DocumentElasticsearchRepository extends ElasticsearchRepository<DocumentElasticsearch, String> {

//    List<DocumentElasticsearch> findByTitleContaining(String keyword);
//
//    List<DocumentElasticsearch> findByAuthorContainingOrDescriptionContaining(String authorKeyword, String descriptionKeyword);

    List<DocumentElasticsearch> findByTitleOrFileNameOrExtractedContentOrAuthorOrDescriptionContaining(
            String titleKeyword, String fileNameKeyword, String contentKeyword, String authorKeyword, String descriptionKeyword);

}
