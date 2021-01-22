/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package service;

import abstractFacades.AbstractEmployeeFacade;
import abstractFacades.AbstractFacade;
import entity.Boss;
import entity.Employee;
import exception.CreateException;
import exception.DeleteException;
import exception.EmailExistException;
import exception.LoginExistException;
import exception.ReadException;
import exception.UpdateException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.GET;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

/**
 * RESTful service for Employee entity. Includes CRUD operations.
 *
 * @author Xabier Carnero, Endika Ubierna, Markel Lopez de Uralde.
 * @since 04/12/2020
 * @version 1.0
 */
@Stateless
@Path("employee")
public class EmployeeFacadeREST extends AbstractEmployeeFacade {

    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(EmployeeFacadeREST.class.getName());
    /**
     * EntityManager for EMEX51CRUDServerPU persistence unit. Injects an
     * {@link EntityManager} instance.
     */
    @PersistenceContext(unitName = "EMEX51CRUDServerPU")
    private EntityManager em;

    /**
     * Class constructor. Call to the super class {@link AbstractFacade}.
     */
    public EmployeeFacadeREST() {
        super(Employee.class);
    }

    /**
     * Create (Insert) operation after receiving a Post HTTP order.
     *
     * @param employee The employee object in xml format.
     * @param id
     */
    @POST
    @Consumes({MediaType.APPLICATION_XML})
    public void create(Employee employee) {
        LOGGER.log(Level.INFO, "Metodo create Boss de la clase EmployeeFacade");
        try {
            super.createEmployee(employee);
        } catch (CreateException ex) {
            Logger.getLogger(ArmyFacadeREST.class.getName()).log(Level.SEVERE, null, ex);
            throw new InternalServerErrorException(ex);
        } catch (EmailExistException ex) {
            Logger.getLogger(AbstractEmployeeFacade.class.getName()).log(Level.SEVERE, null, ex);
            throw new ForbiddenException(ex);
        } catch (LoginExistException ex) {
            Logger.getLogger(EmployeeFacadeREST.class.getName()).log(Level.SEVERE, null, ex);
            throw new NotAuthorizedException(ex);
        }
    }

    /**
     * Edit (Update) operation after receiving a Delete HTTP order.
     *
     * @param entity The employee object in xml format.
     */
    @PUT
    @Consumes({MediaType.APPLICATION_XML})
    @Override
    public void edit(Employee entity) {
        LOGGER.log(Level.INFO, "Metodo edit de la clase EmployeeFacade");
        try {
            super.edit(entity);
        } catch (UpdateException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * Remove (Delete) operation after receiving a Delete HTTP order.
     *
     * @param id An id value of an employee.
     */
    @DELETE
    @Path("{id}")
    public void remove(@PathParam("id") Integer id) {
        LOGGER.log(Level.INFO, "Metodo remove de la clase EmployeeFacade");
        try {
            super.remove(super.find(id));
        } catch (ReadException | DeleteException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * Find (Select) operation after receiving a Get HTTP order.
     *
     * @param id An id value of an employee.
     * @return An Employee object in xml format.
     */
    @GET
    @Path("{id}")
    @Produces({MediaType.APPLICATION_XML})
    public Employee find(@PathParam("id") Integer id) {
        LOGGER.log(Level.INFO, "Metodo find de la clase EmployeeFacade");
        try {
            return super.find(id);
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * Gets all the {@link Employee} of Area51.
     *
     * @return A list of <code>Employee</code>.
     */
    @GET
    @Path("all")
    @Produces({MediaType.APPLICATION_XML})
    public List<Employee> findAllEmployees() {
        LOGGER.log(Level.INFO, "Metodo findAllEmployees de la clase EmployeeFacade");
        try {
            return super.getAllEmployees();
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * Gets a <code>List</code> {@link Employee} of Area51 with the same name as
     * the one passed by the parameter.
     *
     * @param name A String with the name of a <code>Employee</code>.
     * @return A list of <code>Employee</code>.
     */
    @GET
    @Path("name/{name}")
    @Produces({MediaType.APPLICATION_XML})
    public List<Employee> findEmployeesByName(@PathParam("name") String name) {
        try {
            LOGGER.log(Level.INFO, "Metodo find por nombre de la clase EmployeeFacade");
            return super.getEmployeesByName(name);
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * Gets a <code>List</code> {@link Employee} of Area51 with the same name as
     * the one passed by the parameter.
     *
     * @param name A String with the name of a <code>Employee</code>.
     * @return A list of <code>Employee</code>.
     */
    @GET
    @Path("email/{email}")
    @Produces({MediaType.APPLICATION_XML})
    public Employee findEmployeeByEmail(@PathParam("email") String email) {
        try {
            LOGGER.log(Level.INFO, "Metodo find por nombre de la clase VisitorFacade");
            return super.getEmployeeByEmail(email);
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * Gets an {@link EntityManager} instance.
     *
     * @return An {@link EntityManager} instance.
     */
    @Override
    protected EntityManager getEntityManager() {
        LOGGER.log(Level.INFO, "Metodo getEntityManager de la clase EmployeeFacade");
        return em;
    }

}
