/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package service;

import entity.Visitor;
import exception.CreateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

/**
 * RESTful service for Visitor entity. Includes CRUD operations.
 *
 * @author Xabier Carnero, Endika Ubierna, Markel Uralde
 * @since 04/12/2020
 * @version 1.0
 */
@Stateless
@Path("visitor")
public class VisitorFacadeREST extends AbstractFacade<Visitor> {

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
     * @param entity The visitor object in xml format.
     */
    @POST
    @Override
    @Consumes({MediaType.APPLICATION_XML})
    public void create(Visitor entity) {
        LOGGER.log(Level.INFO, "Metodo create de la clase VisitorFacade");
        try {
            super.create(entity);
        } catch (CreateException ex) {
            Logger.getLogger(ArmyFacadeREST.class.getName()).log(Level.SEVERE, null, ex);
            throw new InternalServerErrorException(ex);
        }
    }

    /**
     * Edit (Update) operation after receiving a Delete HTTP order.
     *
     * @param entity The visitor object in xml format.
     */
    @PUT
    @Consumes({MediaType.APPLICATION_XML})
    public void edit(Visitor entity) {
        LOGGER.log(Level.INFO, "Metodo edit de la clase VisitorFacade");
        super.edit(entity);
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
        super.remove(super.find(id));
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
        return super.find(id);
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
