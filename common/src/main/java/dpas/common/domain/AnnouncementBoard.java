package dpas.common.domain;

import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullAnnouncementException;
import dpas.common.domain.exception.NullUserException;

import java.util.Comparator;
import java.util.List;

public interface AnnouncementBoard {

    String getIdentifier();

    void post(Announcement announcement)
            throws NullAnnouncementException, NullUserException, InvalidUserException;

    List<Announcement> read(int number) throws InvalidNumberOfPostsException;

    long getSeq();
}
