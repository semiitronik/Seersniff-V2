package com.seersniff.seersniff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class SeerSniffApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(SeerSniffApiApplication.class, args);
	}
}
