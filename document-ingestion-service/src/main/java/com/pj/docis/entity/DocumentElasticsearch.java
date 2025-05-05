package com.pj.docis.entity;

import jakarta.persistence.Column;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.Document;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.elasticsearch.annotations.FieldType;
import org.springframework.data.elasticsearch.annotations.Setting;

import java.util.Date;

@Document(indexName = "documents")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class DocumentElasticsearch {

    @Id
    private String id;

    @Field(type = FieldType.Text, analyzer = "english")
    private String title;

    @Field(type = FieldType.Text, analyzer = "english")
    private String fileName;

    @Field(type = FieldType.Text)
    private String fileUrl;

    @Field(type = FieldType.Keyword)
    private String mimeType;

    @Field(type = FieldType.Text)
    private String author;

    @Field(type = FieldType.Text)
    private String metadataString;

    @Field(type = FieldType.Date)
    private Date uploadDate;

    @Field(type = FieldType.Text)
    private String extractedContent;
}
