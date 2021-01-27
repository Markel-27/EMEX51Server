/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package service;

import abstractFacades.AbstractFacade;
import abstractFacades.AbstractVisitorFacade;
import entity.Visitor;
import exception.CreateException;
import exception.DeleteException;
import exception.EmailExistException;
import exception.IncorrectPasswordException;
import exception.LoginExistException;
import exception.LoginNotExistException;
import exception.ReadException;
import exception.UpdateException;
import java.util.ArrayList;
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
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

/**
 * RESTful service for Visitor entity. Includes CRUD operations.
 *
 * @author Xabier Carnero, Endika Ubierna, Markel Lopez de Uralde
 * @since 04/12/2020
 * @version 1.0
 */
@Stateless
@Path("visitor")
public class VisitorFacadeREST extends AbstractVisitorFacade {

    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(VisitorFacadeREST.class.getName());
    /**
     * EntityManager for EMEX51CRUDServerPU persistence unit. Injects an
     * {@link EntityManager} instance.
     */
    @PersistenceContext(unitName = "EMEX51CRUDServerPU")
    private EntityManager em;

    /**
     * Class constructor. Call to the super class {@link AbstractFacade}.
     */
    public VisitorFacadeREST() {
        super(Visitor.class);
    }

    /**
     * Create (Insert) operation after receiving a Post HTTP order.
     *
     * @param visitor
     */
    @POST
    @Override
    @Consumes({MediaType.APPLICATION_XML})
    public void create(Visitor visitor) {
        LOGGER.log(Level.INFO, "Metodo create Visitor de la clase VisitorFacade");
        try {
            super.createVisitor(visitor);
        } catch (CreateException ex) {
            Logger.getLogger(VisitorFacadeREST.class.getName()).log(Level.SEVERE, null, ex);
            throw new InternalServerErrorException(ex);
        } catch (EmailExistException ex) {
            Logger.getLogger(AbstractVisitorFacade.class.getName()).log(Level.SEVERE, null, ex);
            throw new ForbiddenException(ex);
        } catch (LoginExistException ex) {
            Logger.getLogger(AbstractVisitorFacade.class.getName()).log(Level.SEVERE, null, ex);
            throw new ForbiddenException(ex);
        }
    }

    /**
     * Edit (Update) operation after receiving a Delete HTTP order.
     *
     * @param entity The visitor object in xml format.
     */
    @PUT
    @Consumes({MediaType.APPLICATION_XML})
    @Override
    public void edit(Visitor entity) {
        LOGGER.log(Level.INFO, "Metodo edit de la clase VisitorFacade");
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
     * @param id An id value of a visitor.
     */
    @DELETE
    @Path("{id}")
    public void remove(@PathParam("id") Integer id) {
        LOGGER.log(Level.INFO, "Metodo remove de la clase VisitorFacade");
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
     * @param id An id value of a visitor.
     * @return A Visitor object in xml format.
     */
    @GET
    @Path("{id}")
    @Produces({MediaType.APPLICATION_XML})
    public Visitor find(@PathParam("id") Integer id) {
        LOGGER.log(Level.INFO, "Metodo find de la clase VisitorFacade");
        try {
            Visitor visitor = super.find(id);
            getEntityManager().detach(visitor);
            visitor.setPassword("");
            return visitor;
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * This method finds all Area51 visitors.
     *
     * @return A list containing visitors.
     */
    @GET
    @Path("all")
    @Produces({MediaType.APPLICATION_XML})
    public List<Visitor> findAllVisitors() {
        LOGGER.log(Level.INFO, "Metodo findAllArmys de la clase VisitorFacade");
        try {
            List<Visitor> visitors = super.getAllVisitors();
            for (Visitor v : visitors) {
                getEntityManager().detach(v);
                v.setPassword("");
            }
            return visitors;
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * This method finds a <code>Visitor</code> by the class attributes login
     * and password.
     *
     * @param login
     * @param password
     * @return A list of visitors.
     */
    @GET
    @Path("loginVisitor/{login}/{password}")
    @Produces({MediaType.APPLICATION_XML})
    public Visitor loginVisitor(@PathParam("login") String login, @PathParam("password") String password) {
        try {
            LOGGER.log(Level.INFO, "Metodo login Visitor de la clase VisitorFacade");
            Visitor visitor = super.makeVisitorLogin(login, password);
            getEntityManager().detach(visitor);
            visitor.setPassword("");
            return visitor;
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        } catch (LoginNotExistException ex) {
            Logger.getLogger(VisitorFacadeREST.class.getName()).log(Level.SEVERE, null, ex);
            throw new NotFoundException(ex);
        } catch (IncorrectPasswordException ex) {
            Logger.getLogger(VisitorFacadeREST.class.getName()).log(Level.SEVERE, null, ex);
            throw new NotAuthorizedException(ex);
        }
    }

    /**
     * This method finds a list of <code>Visitor</code> by the class attribute
     * name.
     *
     * @param name The class attribure name.
     * @return A list of visitors.
     */
    @GET
    @Path("name/{name}")
    @Produces({MediaType.APPLICATION_XML})
    public List<Visitor> findVisitorsByName(@PathParam("name") String name) {
        try {
            LOGGER.log(Level.INFO, "Metodo find por nombre de la clase VisitorFacade");
            List<Visitor> visitors = super.getVisitorsByName(name);
            for (Visitor v : visitors) {
                getEntityManager().detach(v);
                v.setPassword("");
            }
            return visitors;
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
        LOGGER.log(Level.INFO, "Metodo getEntityManager de la clase VisitorFacade");
        return em;
    }

}
