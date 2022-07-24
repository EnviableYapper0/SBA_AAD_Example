package com.enviableyapper0.sbaserver

import de.codecentric.boot.admin.server.config.EnableAdminServer
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@EnableAdminServer
@SpringBootApplication
class SbaServerApplication

fun main(args: Array<String>) {
	runApplication<SbaServerApplication>(*args)
}
