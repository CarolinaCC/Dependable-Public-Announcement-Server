package dpas.common.domain;

import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullPostException;
import dpas.common.domain.exception.NullUserException;

public interface AnnouncementBoard {

    public void post(User user, Post post) throws NullPostException, NullUserException, InvalidUserException;

    public Post[] read(int number) throws InvalidNumberOfPostsException;

}
