package org.fm.rest;


public class Admin {
    private String name;
    private String email;

    public Admin() {
    }

    public Admin(String name, String email) {
        this.name = name;
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}

package org.fm.rest;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
public class AdminRestService {
    private static final List<Admin> admins;

    static {
        admins = new ArrayList<>();
        admins.add(new Admin("Test1", "Security"));
        admins.add(new Admin("Test2", "Security"));
    }

    @RequestMapping(path = "/admins", method = RequestMethod.GET)
    public static List<Admin> getPersons() {
        return admins;
    }

    @RequestMapping(path = "/admins/{name}", method = RequestMethod.GET)
    public static Admin getPerson(@PathVariable("name") String name) {
        return admins.stream()
                .filter(person -> name.equalsIgnoreCase(person.getName()))
                .findAny().orElse(null);
    }
}

