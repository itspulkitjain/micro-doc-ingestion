package com.pj.docis;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class DocumentIngestionServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(DocumentIngestionServiceApplication.class, args);
	}

}
