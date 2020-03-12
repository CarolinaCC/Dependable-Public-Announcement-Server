package dpas.common.domain;

import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullPostException;
import dpas.common.domain.exception.NullUserException;

public interface AnnouncementBoard {

    public void post(User user, Announcement announcement) throws NullPostException, NullUserException, InvalidUserException;

    //FIXME This could return an ArrayList maybe it would be simpler?
    //(It's really as you wish)
    public Announcement[] read(int number) throws InvalidNumberOfPostsException;

}
