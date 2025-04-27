package com.pj.docis.dto;

import com.pj.docis.entity.DocumentEntity;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

import java.time.ZonedDateTime;
import java.util.List;

@Mapper(imports = {ZonedDateTime.class})
public interface DocumentMapper {

    public DocumentMapper mapper = Mappers.getMapper(DocumentMapper.class);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "fileUrl", ignore = true)
    @Mapping(target = "content", ignore = true)
    @Mapping(target = "author", ignore = true)
    @Mapping(target = "uploadDate", ignore = true)
    DocumentEntity toEntity(DocumentRequest documentRequest);

    @Mapping(target = "content", ignore = true)
    Document toJson(DocumentEntity documentEntity);

    List<Document> toJsons(List<DocumentEntity> documentEntities);

}
