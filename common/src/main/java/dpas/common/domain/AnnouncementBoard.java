package dpas.common.domain;

import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullPostException;
import dpas.common.domain.exception.NullUserException;

import java.util.ArrayList;

public interface AnnouncementBoard {

    public void post(User user, Announcement announcement) throws NullPostException, NullUserException, InvalidUserException;

    public ArrayList<Announcement> read(int number) throws InvalidNumberOfPostsException;

}
